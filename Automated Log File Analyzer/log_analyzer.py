"""Automated log file analyzer.

Scans one or more text log files for patterns that may indicate security
events (failed logins, access-denied errors, injection signatures, etc.) and
prints a grouped summary with sample lines. Supports JSON output for piping
into other tools.

Usage:
    python log_analyzer.py /var/log/auth.log
    python log_analyzer.py auth.log app.log --min-severity high
    python log_analyzer.py auth.log --json > alerts.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass

Severity = str  # "low" | "medium" | "high"


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern[str]
    description: str
    severity: Severity


def _rule(regex: str, description: str, severity: Severity) -> Rule:
    return Rule(re.compile(regex, re.IGNORECASE), description, severity)


ALERT_RULES: tuple[Rule, ...] = (
    _rule(r"failed password for invalid user", "Failed login with invalid user", "high"),
    _rule(r"authentication failure", "Authentication failure", "medium"),
    _rule(r"failed (login|password)", "Failed login attempt", "medium"),
    _rule(r"accepted password for root|root login", "Root login", "high"),
    _rule(r"unauthorized access", "Unauthorized access attempt", "high"),
    _rule(r"access denied|permission denied", "Access denied", "low"),
    _rule(r"sql syntax|sql injection|union select", "Possible SQL injection", "high"),
    _rule(r"<script>|onerror\s*=|xss", "Possible XSS attempt", "high"),
    _rule(r"segfault|kernel panic", "System fault", "medium"),
)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Hit:
    line_number: int
    text: str


def analyze_file(path: str, min_severity: Severity = "low") -> dict[str, list[Hit]]:
    """Return a mapping of alert description -> list of matching lines."""
    threshold = SEVERITY_ORDER[min_severity]
    hits: dict[str, list[Hit]] = defaultdict(list)

    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line_number, line in enumerate(handle, 1):
            for rule in ALERT_RULES:
                if SEVERITY_ORDER[rule.severity] < threshold:
                    continue
                if rule.pattern.search(line):
                    hits[f"[{rule.severity.upper()}] {rule.description}"].append(
                        Hit(line_number, line.strip())
                    )
    return hits


def _print_human(path: str, hits: dict[str, list[Hit]], samples: int) -> None:
    if not hits:
        print(f"{path}: no suspicious patterns found.")
        return
    print(f"\n=== {path} ===")
    for description, items in sorted(hits.items(), reverse=True):
        print(f"{description}: {len(items)} occurrence(s)")
        for hit in items[:samples]:
            print(f"    line {hit.line_number}: {hit.text}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="log files to analyze")
    parser.add_argument(
        "--min-severity", choices=("low", "medium", "high"), default="low",
        help="only report alerts at or above this severity",
    )
    parser.add_argument("--samples", type=int, default=3, help="sample lines per alert")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    report: dict[str, dict[str, list[dict[str, object]]]] = {}
    exit_code = 0

    for path in args.files:
        try:
            hits = analyze_file(path, args.min_severity)
        except FileNotFoundError:
            print(f"error: file not found: {path}", file=sys.stderr)
            exit_code = 1
            continue
        except OSError as exc:
            print(f"error: could not read {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue

        if args.json:
            report[path] = {
                desc: [{"line": h.line_number, "text": h.text} for h in items]
                for desc, items in hits.items()
            }
        else:
            _print_human(path, hits, args.samples)

    if args.json:
        print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
