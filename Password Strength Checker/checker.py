"""Password strength checker.

Scores a password out of 100 using character variety, length, and a set of
penalties for common weak patterns (dictionary words, repeats, sequences).
This is a heuristic teaching tool; for production-grade estimation use a
library such as `zxcvbn`.

Usage:
    python checker.py                 # prompts (input hidden)
    python checker.py --password pw   # non-interactive (avoid in shared shells)
"""

from __future__ import annotations

import argparse
import getpass
import re
import sys
from dataclasses import dataclass, field

# A small sample of the most common leaked passwords. A real checker would
# load a large list (e.g. the "Have I Been Pwned" top-N) from a file.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "welcome", "iloveyou",
    "monkey", "dragon", "sunshine", "princess", "football", "password1",
}

SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")


@dataclass
class Result:
    score: int                       # 0-100
    label: str                       # Very weak .. Very strong
    feedback: list[str] = field(default_factory=list)


def _has_sequence(password: str, run: int = 3) -> bool:
    low = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - run + 1):
            if seq[i:i + run] in low:
                return True
    return False


def _has_long_repeat(password: str, run: int = 3) -> bool:
    return re.search(r"(.)\1{" + str(run - 1) + r",}", password) is not None


def check_strength(password: str) -> Result:
    """Return a :class:`Result` scoring ``password`` out of 100."""
    feedback: list[str] = []

    if password.lower() in COMMON_PASSWORDS:
        return Result(0, "Very weak", ["This is one of the most common passwords — never use it."])

    score = 0

    # Length is the single biggest factor.
    length = len(password)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 15
        feedback.append("Aim for 12+ characters; longer beats complex.")
    else:
        feedback.append("Too short — use at least 12 characters.")

    # Character variety.
    classes = {
        "lowercase letters": r"[a-z]",
        "uppercase letters": r"[A-Z]",
        "numbers": r"\d",
        "symbols": r"[^A-Za-z0-9]",
    }
    present = [name for name, pat in classes.items() if re.search(pat, password)]
    score += 15 * len(present)
    missing = [name for name in classes if name not in present]
    if missing:
        feedback.append("Add " + ", ".join(missing) + ".")

    # Penalties for predictable structure.
    if _has_long_repeat(password):
        score -= 15
        feedback.append("Avoid repeating the same character (e.g. 'aaaa').")
    if _has_sequence(password):
        score -= 15
        feedback.append("Avoid sequences like 'abc', '123', or 'qwerty'.")

    score = max(0, min(100, score))

    label = (
        "Very strong" if score >= 85
        else "Strong" if score >= 70
        else "Moderate" if score >= 45
        else "Weak" if score >= 20
        else "Very weak"
    )
    if not feedback:
        feedback.append("Looks solid. Use a password manager so you never reuse it.")

    return Result(score, label, feedback)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--password",
        help="password to check (omit to be prompted with hidden input)",
    )
    args = parser.parse_args(argv)

    password = args.password if args.password is not None else getpass.getpass("Enter a password to check: ")
    result = check_strength(password)

    print(f"\nStrength: {result.label} ({result.score}/100)")
    for item in result.feedback:
        print(f"  - {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
