"""TCP port scanner with service banner grabbing.

For each open port it also tries to read a service banner (and sends a minimal
HTTP request on web ports, which otherwise stay silent). Uses a bounded thread
pool for speed.

    ⚠  Authorized use only. Scan only hosts you own or have explicit written
       permission to test.

Usage:
    python port_scanner_banner.py 127.0.0.1
    python port_scanner_banner.py 192.168.1.10 --ports 1-1024 --workers 200
    python port_scanner_banner.py example.com --ports 22,80,443
"""

from __future__ import annotations

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

WEB_PORTS = {80, 8080, 8000, 443}


@dataclass
class OpenPort:
    port: int
    banner: str


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"port(s) out of range 1-65535: {bad}")
    return sorted(ports)


def grab_banner(sock: socket.socket, host: str, port: int) -> str:
    sock.settimeout(2)
    try:
        if port in WEB_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(1024)
        return data.decode(errors="replace").strip().splitlines()[0] if data else ""
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float) -> OpenPort | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return None
        return OpenPort(port, grab_banner(sock, host, port))


def scan(host: str, ports: list[int], workers: int, timeout: float) -> list[OpenPort]:
    results: list[OpenPort] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_port, host, port, timeout) for port in ports]
        for future in as_completed(futures):
            try:
                result = future.result()
            except OSError:
                continue
            if result is not None:
                label = f"  {result.banner}" if result.banner else ""
                print(f"  port {result.port:5d}  open{label}")
                results.append(result)
    return sorted(results, key=lambda r: r.port)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("--ports", default="1-1024", help="range '1-1024' or list '22,80,443'")
    parser.add_argument("--workers", type=int, default=100, help="concurrent connections")
    parser.add_argument("--timeout", type=float, default=1.0, help="per-port timeout seconds")
    args = parser.parse_args(argv)

    try:
        host = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"error: could not resolve host: {args.target}", file=sys.stderr)
        return 1
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Scanning {args.target} ({host}) — {len(ports)} port(s)")
    open_ports = scan(host, ports, args.workers, args.timeout)
    print(f"\nDone. {len(open_ports)} open port(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
