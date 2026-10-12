# Encrypted Chat Application (AES-GCM)

A minimal two-party chat over TCP where every message is encrypted with
**AES-256-GCM**. The passphrase is shared out of band and never sent over the
wire — both ends derive the same key from it.

## Files

| File | Role |
|------|------|
| `crypto_channel.py` | Shared encryption + message-framing helpers. |
| `server.py` | Listens for one client and exchanges messages. |
| `client.py` | Connects to the server. |

## Setup

```bash
pip install -r requirements.txt
```

## Run it

In one terminal:

```bash
python server.py --passphrase hunter2
```

In another (same machine, or pass `--host`/`--port` for a LAN):

```bash
python client.py --passphrase hunter2
```

Type messages on either side; type `exit` to quit.

## What changed in this rewrite

The original used **AES in ECB mode with a hard-coded 16-byte key**. That has
two serious problems this version fixes:

1. **ECB leaks structure.** Identical plaintext blocks produce identical
   ciphertext blocks, so patterns in your messages stay visible. This version
   uses **GCM** with a fresh random nonce per message.
2. **No integrity.** ECB has no authentication tag, so an attacker could
   flip bits undetected. GCM authenticates every message and rejects
   tampered ones.

It also replaces the hard-coded key with a **passphrase-derived key**
(PBKDF2-HMAC-SHA256), adds **length-prefixed framing** so messages can't run
together on the stream, and makes the chat **bidirectional**.

## Scope and limitations

This is a learning demo, not a secure messenger. It uses a fixed salt and a
long-lived shared key, has no forward secrecy, and does no identity
verification. A real design would run an authenticated key-exchange handshake
(e.g. ephemeral Diffie-Hellman) per session.
