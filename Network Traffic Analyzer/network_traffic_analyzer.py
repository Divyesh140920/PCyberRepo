"""Network traffic analyzer (protocol breakdown).

Captures packets and periodically prints a live breakdown of traffic by
protocol (TCP / UDP / ICMP / other) plus the busiest talkers. Requires scapy
and root/administrator privileges.

    ⚠  Authorized use only. Monitor only networks you own or are explicitly
       permitted to observe.

Usage (run with sudo / as administrator):
    sudo python network_traffic_analyzer.py
    sudo python network_traffic_analyzer.py --iface eth0 --interval 10 --duration 60
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from collections import Counter


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.protocols: Counter[str] = Counter()
        self.sources: Counter[str] = Counter()

    def record(self, protocol: str, src: str | None) -> None:
        with self._lock:
            self.protocols[protocol] += 1
            if src:
                self.sources[src] += 1

    def snapshot(self) -> tuple[Counter[str], Counter[str]]:
        with self._lock:
            return self.protocols.copy(), self.sources.copy()


def _make_handler(stats: Stats):
    from scapy.all import IP, TCP, UDP, ICMP

    def handler(packet) -> None:
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "Other"
        src = packet[IP].src if IP in packet else None
        stats.record(proto, src)

    return handler


def _reporter(stats: Stats, interval: int, stop: threading.Event) -> None:
    while not stop.wait(interval):
        protocols, sources = stats.snapshot()
        total = sum(protocols.values())
        print("\n=== Traffic (last snapshot) ===")
        if total == 0:
            print("No packets captured yet…")
            continue
        print(f"Total packets: {total}")
        for proto in ("TCP", "UDP", "ICMP", "Other"):
            count = protocols.get(proto, 0)
            print(f"  {proto:5s} {count:7d}  ({count / total:5.1%})")
        if sources:
            print("Top talkers:")
            for ip, count in sources.most_common(5):
                print(f"  {ip:>15s}  {count}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iface", help="interface to capture on")
    parser.add_argument("--interval", type=int, default=5, help="seconds between reports")
    parser.add_argument("--duration", type=int, default=0, help="stop after N seconds (0 = until Ctrl+C)")
    args = parser.parse_args(argv)

    try:
        from scapy.all import sniff
    except ImportError:
        print("error: scapy is required (pip install scapy).", file=sys.stderr)
        return 1

    stats = Stats()
    stop = threading.Event()
    reporter = threading.Thread(target=_reporter, args=(stats, args.interval, stop), daemon=True)
    reporter.start()

    print("Capturing traffic… (Ctrl+C to stop)")
    try:
        sniff(
            iface=args.iface,
            prn=_make_handler(stats),
            store=False,
            timeout=args.duration or None,
        )
    except PermissionError:
        print("error: capture needs root/administrator privileges.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
