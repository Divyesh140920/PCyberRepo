"""Packet sniffer (educational network monitoring).

Captures packets on an interface and prints a one-line summary per packet:
source/destination IP, protocol, and (where visible) DNS queries and HTTP
hints. Requires scapy and root/administrator privileges.

    ⚠  Authorized use only. Capture traffic only on networks you own or are
       explicitly permitted to monitor. Intercepting others' traffic may be
       illegal.

Usage (run with sudo / as administrator):
    sudo python sniffer.py
    sudo python sniffer.py --iface eth0 --count 50 --filter "tcp port 80"
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime


def _make_handler():
    from scapy.all import IP, TCP, UDP, DNS, Raw

    def process_packet(packet) -> None:
        if IP not in packet:
            return
        ip = packet[IP]
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else str(ip.proto)
        parts = [f"[{datetime.now():%H:%M:%S}] {ip.src} → {ip.dst}  {proto}"]

        if DNS in packet and packet[DNS].qd is not None:
            try:
                parts.append(f"DNS {packet[DNS].qd.qname.decode(errors='replace')}")
            except (AttributeError, UnicodeDecodeError):
                pass

        if Raw in packet and TCP in packet and 80 in (packet[TCP].sport, packet[TCP].dport):
            payload = bytes(packet[Raw].load)
            if b"HTTP" in payload:
                parts.append("HTTP")

        print("  |  ".join(parts))

    return process_packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iface", help="interface to capture on (default: scapy's default)")
    parser.add_argument("--count", type=int, default=0, help="stop after N packets (0 = unlimited)")
    parser.add_argument("--filter", default="ip", help="BPF filter expression")
    args = parser.parse_args(argv)

    try:
        from scapy.all import sniff
    except ImportError:
        print("error: scapy is required (pip install scapy).", file=sys.stderr)
        return 1

    print("Starting packet capture… (Ctrl+C to stop)")
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=_make_handler(),
            store=False,
            count=args.count,
        )
    except PermissionError:
        print("error: packet capture needs root/administrator privileges.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
