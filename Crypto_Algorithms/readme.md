# Crypto Algorithms

Small, self-contained implementations of three classic cryptographic schemes,
written for learning. Each script is a command-line tool with its own
`--help`.

| Script | Scheme | Notes |
|--------|--------|-------|
| `caesar_cipher.py` | Caesar substitution cipher | Educational only — trivially breakable; includes a brute-force cracker. |
| `aes_cipher.py` | AES-256-GCM (authenticated) | Passphrase-based, with PBKDF2 key derivation and tamper detection. |
| `rsa_cipher.py` | RSA-2048 with OAEP | Key-pair generation plus encrypt/decrypt of short messages. |

## Setup

```bash
pip install -r requirements.txt
```

## Examples

```bash
# Caesar
python caesar_cipher.py encrypt --shift 3 "Attack at dawn"
python caesar_cipher.py crack "Dwwdfn dw gdzq"

# AES-GCM (authenticated symmetric encryption)
token=$(python aes_cipher.py encrypt --passphrase hunter2 "secret message")
python aes_cipher.py decrypt --passphrase hunter2 "$token"

# RSA (public-key encryption)
python rsa_cipher.py genkeys --out-dir keys/
token=$(python rsa_cipher.py encrypt --public keys/public.pem "hello")
python rsa_cipher.py decrypt --private keys/private.pem "$token"
```

## What changed in this rewrite

- **AES now uses GCM, not CBC.** The previous version used CBC mode with
  hand-written padding and *no authentication tag*, so tampered ciphertext
  would silently decrypt to garbage. GCM detects tampering and fails loudly.
- **Keys are derived from passphrases** with PBKDF2-HMAC-SHA256 and a random
  salt, instead of being passed as raw bytes.
- Every script is now a proper CLI with argument parsing and error handling.

> These implementations are for education. For production use a vetted library
> such as [`cryptography`](https://cryptography.io/) and established protocols.
