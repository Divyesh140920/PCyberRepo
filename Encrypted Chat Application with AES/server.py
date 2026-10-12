"""Encrypted chat server (AES-256-GCM).

Accepts a single client and relays encrypted messages both ways over one TCP
connection. The passphrase is never sent over the network — both ends derive
the key independently, so start the server and client with the same one.

Usage:
    python server.py --passphrase hunter2
    python server.py --host 0.0.0.0 --port 12345 --passphrase hunter2
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading

from crypto_channel import derive_key, recv_message, send_message


def _reader(conn: socket.socket, key: bytes, stop: threading.Event) -> None:
    """Print messages from the peer until the connection closes."""
    while not stop.is_set():
        try:
            msg = recv_message(conn, key)
        except ValueError:
            print("\n[!] Dropped a message that failed authentication.")
            continue
        if msg is None:
            print("\n[peer disconnected]")
            stop.set()
            break
        print(f"\nclient: {msg}\nyou: ", end="", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1", help="bind address")
    parser.add_argument("--port", type=int, default=12345, help="bind port")
    parser.add_argument("--passphrase", required=True, help="shared secret passphrase")
    args = parser.parse_args(argv)

    key = derive_key(args.passphrase)
    stop = threading.Event()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(1)
        print(f"[listening] {args.host}:{args.port} — waiting for a client…")

        conn, addr = server.accept()
        with conn:
            print(f"[connected] {addr[0]}:{addr[1]}  (type 'exit' to quit)\nyou: ", end="", flush=True)
            threading.Thread(target=_reader, args=(conn, key, stop), daemon=True).start()
            try:
                while not stop.is_set():
                    line = sys.stdin.readline()
                    if not line or line.strip().lower() == "exit":
                        break
                    send_message(conn, key, line.rstrip("\n"))
            except (KeyboardInterrupt, BrokenPipeError):
                pass
            finally:
                stop.set()
    print("\n[server closed]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
