"""RSA public-key encryption demo (RSA-2048 with OAEP padding).

Demonstrates generating an RSA key pair, saving the keys to PEM files, and
encrypting / decrypting short messages with OAEP padding (the secure default
for RSA encryption). RSA can only encrypt data smaller than the key size, so
in real systems it is used to wrap a symmetric key rather than bulk data —
this demo keeps messages short to stay within that limit.

Requires ``pycryptodome`` (see requirements.txt).

Usage:
    python rsa_cipher.py genkeys --out-dir keys/
    python rsa_cipher.py encrypt --public keys/public.pem "hello" > msg.b64
    python rsa_cipher.py decrypt --private keys/private.pem "$(cat msg.b64)"
"""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

KEY_BITS = 2048


def generate_keys() -> tuple[bytes, bytes]:
    """Return ``(private_pem, public_pem)`` for a fresh RSA key pair."""
    key = RSA.generate(KEY_BITS)
    return key.export_key(), key.publickey().export_key()


def encrypt(public_pem: bytes, plaintext: str) -> str:
    cipher = PKCS1_OAEP.new(RSA.import_key(public_pem))
    return base64.b64encode(cipher.encrypt(plaintext.encode("utf-8"))).decode("ascii")


def decrypt(private_pem: bytes, token: str) -> str:
    cipher = PKCS1_OAEP.new(RSA.import_key(private_pem))
    return cipher.decrypt(base64.b64decode(token)).decode("utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("genkeys", help="generate a key pair and write PEM files")
    g.add_argument("--out-dir", default=".", help="directory for private.pem / public.pem")

    e = sub.add_parser("encrypt", help="encrypt with a public key")
    e.add_argument("--public", required=True, help="path to public.pem")
    e.add_argument("text", help="message to encrypt")

    d = sub.add_parser("decrypt", help="decrypt with a private key")
    d.add_argument("--private", required=True, help="path to private.pem")
    d.add_argument("token", help="base64 ciphertext")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "genkeys":
            private_pem, public_pem = generate_keys()
            out = Path(args.out_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "private.pem").write_bytes(private_pem)
            (out / "public.pem").write_bytes(public_pem)
            # Keep the private key readable only by the owner.
            (out / "private.pem").chmod(0o600)
            print(f"Wrote {out/'private.pem'} and {out/'public.pem'}")
        elif args.command == "encrypt":
            public_pem = Path(args.public).read_bytes()
            print(encrypt(public_pem, args.text))
        else:
            private_pem = Path(args.private).read_bytes()
            print(decrypt(private_pem, args.token))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
