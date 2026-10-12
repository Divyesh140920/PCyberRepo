# Network Traffic Analyzer

Captures live packets and prints a periodic breakdown of traffic by protocol
(TCP / UDP / ICMP / other), along with the busiest source addresses.

> ⚠ **Authorized use only.** Monitor only networks you own or are explicitly
> permitted to observe.

## Setup

```bash
pip install -r requirements.txt
```

Requires **root/administrator privileges** to capture.

## Usage

```bash
sudo python network_traffic_analyzer.py
sudo python network_traffic_analyzer.py --iface eth0 --interval 10 --duration 60
```

## Options

| Flag | Meaning |
|------|---------|
| `--iface` | Interface to capture on. |
| `--interval` | Seconds between live reports (default 5). |
| `--duration` | Stop after N seconds (0 = until Ctrl+C). |

## What changed in this rewrite

- **Top-talkers** tracking in addition to the protocol percentages.
- **CLI options** for interface, report interval, and capture duration.
- **Thread-safe stats** wrapped in a small class, and a clean shutdown using
  an `Event` instead of a bare infinite loop.
- Clear errors when scapy is missing or privileges are insufficient.
