"""AES encryption demo using authenticated encryption (AES-GCM).

This rewrite uses **AES-GCM**, which provides both confidentiality *and*
integrity: if the ciphertext (or the associated data) is tampered with,
decryption fails loudly instead of returning garbage. The original version
used CBC mode with hand-rolled padding and no authentication tag, which is a
common and dangerous beginner mistake.

Keys are derived from a passphrase with PBKDF2-HMAC-SHA256 and a random salt,
so the same passphrase does not produce the same key twice. The output token
is ``base64(salt || nonce || ciphertext_with_tag)``.

Requires ``pycryptodome`` (see requirements.txt).

Usage:
    python aes_cipher.py encrypt --passphrase hunter2 "secret message"
    python aes_cipher.py decrypt --passphrase hunter2 <token>
"""

from __future__ import annotations

import argparse
import base64
import sys

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32          # AES-256
PBKDF2_ITERATIONS = 200_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2(
        passphrase,
        salt,
        dkLen=KEY_LEN,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt(passphrase: str, plaintext: str) -> str:
    """Encrypt ``plaintext`` and return a base64 token."""
    salt = get_random_bytes(SALT_LEN)
    nonce = get_random_bytes(NONCE_LEN)
    key = _derive_key(passphrase, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

    return base64.b64encode(salt + nonce + ciphertext + tag).decode("ascii")


def decrypt(passphrase: str, token: str) -> str:
    """Decrypt a base64 token produced by :func:`encrypt`.

    Raises ``ValueError`` if the passphrase is wrong or the data was altered.
    """
    raw = base64.b64decode(token)
    salt, raw = raw[:SALT_LEN], raw[SALT_LEN:]
    nonce, raw = raw[:NONCE_LEN], raw[NONCE_LEN:]
    tag, ciphertext = raw[-16:], raw[:-16]

    key = _derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError("decryption failed: wrong passphrase or tampered data") from exc
    return plaintext.decode("utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name)
        p.add_argument("--passphrase", required=True, help="shared secret passphrase")
        p.add_argument("data", help="plaintext (encrypt) or base64 token (decrypt)")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "encrypt":
            print(encrypt(args.passphrase, args.data))
        else:
            print(decrypt(args.passphrase, args.data))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
