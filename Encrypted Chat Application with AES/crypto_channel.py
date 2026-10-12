"""Shared encryption + framing helpers for the encrypted chat demo.

Messages are protected with **AES-256-GCM**. Both ends derive the same key
from a shared passphrase using PBKDF2 with a fixed, shared salt (fine for a
self-contained demo; a real system would negotiate a fresh key per session,
e.g. with an ephemeral Diffie-Hellman handshake).

Wire format for each message:

    [4-byte big-endian length][12-byte nonce][ciphertext + 16-byte GCM tag]

The length prefix lets the receiver read exactly one message off the stream
at a time, which the original ECB version did not handle.
"""

from __future__ import annotations

import socket
import struct

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# A fixed salt keeps the demo simple: both peers derive the same key from the
# same passphrase. Do NOT reuse this pattern in production.
_DEMO_SALT = b"pcyberrepo-chat-demo-salt"
_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_PBKDF2_ITERATIONS = 200_000


def derive_key(passphrase: str) -> bytes:
    return PBKDF2(
        passphrase,
        _DEMO_SALT,
        dkLen=_KEY_LEN,
        count=_PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt(key: bytes, plaintext: str) -> bytes:
    nonce = get_random_bytes(_NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return nonce + ciphertext + tag


def decrypt(key: bytes, blob: bytes) -> str:
    nonce, rest = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    ciphertext, tag = rest[:-_TAG_LEN], rest[-_TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def send_message(sock: socket.socket, key: bytes, plaintext: str) -> None:
    blob = encrypt(key, plaintext)
    sock.sendall(struct.pack(">I", len(blob)) + blob)


def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly ``n`` bytes, or return ``None`` if the peer closed."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def recv_message(sock: socket.socket, key: bytes) -> str | None:
    """Read one framed message. Returns ``None`` when the connection ends."""
    header = _recv_exactly(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    blob = _recv_exactly(sock, length)
    if blob is None:
        return None
    return decrypt(key, blob)
