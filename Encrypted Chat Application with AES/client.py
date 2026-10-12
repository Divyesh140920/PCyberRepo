"""Encrypted chat client (AES-256-GCM).

Connects to the chat server and exchanges encrypted messages both ways. Use
the same passphrase on both ends — it is never transmitted.

Usage:
    python client.py --passphrase hunter2
    python client.py --host 192.168.1.50 --port 12345 --passphrase hunter2
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading

from crypto_channel import derive_key, recv_message, send_message


def _reader(conn: socket.socket, key: bytes, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            msg = recv_message(conn, key)
        except ValueError:
            print("\n[!] Dropped a message that failed authentication.")
            continue
        if msg is None:
            print("\n[server disconnected]")
            stop.set()
            break
        print(f"\nserver: {msg}\nyou: ", end="", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1", help="server address")
    parser.add_argument("--port", type=int, default=12345, help="server port")
    parser.add_argument("--passphrase", required=True, help="shared secret passphrase")
    args = parser.parse_args(argv)

    key = derive_key(args.passphrase)
    stop = threading.Event()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect((args.host, args.port))
        except OSError as exc:
            print(f"error: could not connect to {args.host}:{args.port}: {exc}", file=sys.stderr)
            return 1

        print(f"[connected] {args.host}:{args.port}  (type 'exit' to quit)\nyou: ", end="", flush=True)
        threading.Thread(target=_reader, args=(client, key, stop), daemon=True).start()
        try:
            while not stop.is_set():
                line = sys.stdin.readline()
                if not line or line.strip().lower() == "exit":
                    break
                send_message(client, key, line.rstrip("\n"))
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            stop.set()
    print("\n[disconnected]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
