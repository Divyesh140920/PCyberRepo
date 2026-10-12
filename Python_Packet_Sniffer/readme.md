# Python Packet Sniffer

Captures live network packets and prints a one-line summary per packet:
source/destination IP, protocol, visible DNS queries, and an HTTP hint on
port 80. A hands-on way to see what network monitoring looks like.

> ⚠ **Authorized use only.** Capture traffic only on networks you own or are
> explicitly permitted to monitor.

## Setup

```bash
pip install -r requirements.txt
```

Packet capture requires **root/administrator privileges**.

## Usage

```bash
sudo python sniffer.py
sudo python sniffer.py --iface eth0 --count 50 --filter "tcp port 80"
```

## Options

| Flag | Meaning |
|------|---------|
| `--iface` | Interface to capture on (default: scapy's default). |
| `--count` | Stop after N packets (0 = run until Ctrl+C). |
| `--filter` | BPF filter expression (e.g. `"tcp port 80"`, `"udp"`). |

## What changed in this rewrite

- **Command-line options** for interface, packet count, and BPF filter.
- **Clear errors** when scapy is missing or privileges are insufficient,
  instead of an unhandled traceback.
- Safer field access (guards around DNS/Raw layers) and a clean Ctrl+C exit.
