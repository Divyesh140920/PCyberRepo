"""Caesar cipher — a classic substitution cipher, for learning only.

The Caesar cipher shifts each letter by a fixed number of positions in the
alphabet. It offers no real security (there are only 25 possible keys and it
is trivially broken by frequency analysis); it is here purely to illustrate
how a basic substitution cipher works.

Usage:
    python caesar_cipher.py encrypt --shift 3 "Attack at dawn"
    python caesar_cipher.py decrypt --shift 3 "Dwwdfn dw gdzq"
    python caesar_cipher.py crack "Dwwdfn dw gdzq"      # try all 25 shifts
"""

from __future__ import annotations

import argparse
import sys


def caesar_shift(text: str, shift: int) -> str:
    """Return ``text`` with every ASCII letter shifted by ``shift`` places."""
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)


def encrypt(plaintext: str, shift: int) -> str:
    return caesar_shift(plaintext, shift)


def decrypt(ciphertext: str, shift: int) -> str:
    return caesar_shift(ciphertext, -shift)


def crack(ciphertext: str) -> list[tuple[int, str]]:
    """Return every possible decryption (brute force over all 25 shifts)."""
    return [(shift, decrypt(ciphertext, shift)) for shift in range(1, 26)]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name, help=f"{name} text with a known shift")
        p.add_argument("text", help="text to process")
        p.add_argument("--shift", type=int, required=True, help="shift amount (0-25)")

    p = sub.add_parser("crack", help="brute-force all 25 shifts")
    p.add_argument("text", help="ciphertext to crack")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "encrypt":
        print(encrypt(args.text, args.shift))
    elif args.command == "decrypt":
        print(decrypt(args.text, args.shift))
    elif args.command == "crack":
        for shift, guess in crack(args.text):
            print(f"shift {shift:2d}: {guess}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
