# Port Scanner with Banner Grabbing

A multithreaded TCP port scanner that also grabs a service banner from each
open port (and sends a minimal HTTP `HEAD` request on web ports so they
reveal their server header).

> ⚠ **Authorized use only.** Scan only hosts you own or have explicit written
> permission to test.

## Usage

```bash
python port_scanner_banner.py 127.0.0.1
python port_scanner_banner.py 192.168.1.10 --ports 1-1024 --workers 200
python port_scanner_banner.py example.com --ports 22,80,443
```

## Options

| Flag | Meaning |
|------|---------|
| `--ports` | Range (`1-1024`) or comma list (`22,80,443`). |
| `--workers` | Concurrent connections (default 100). |
| `--timeout` | Per-port timeout in seconds (default 1.0). |

## What changed in this rewrite

- **Bounded thread pool** instead of one thread per port (the original could
  spawn 1024+ threads at once).
- **Target/ports are CLI arguments**, not hard-coded module globals.
- **Smarter banner grab** — sends an HTTP `HEAD` on web ports and returns the
  first response line, with proper socket cleanup.
- Hostname resolution and input validation.

Standard library only — no dependencies.
