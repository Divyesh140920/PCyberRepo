# Automated Log File Analyzer

Scans text log files for patterns that may indicate security events — failed
logins, root logins, access-denied errors, and injection/XSS signatures — and
prints a grouped summary with sample lines. Each rule has a severity so you
can filter to the noise level you care about.

## Usage

```bash
python log_analyzer.py /var/log/auth.log
python log_analyzer.py auth.log app.log --min-severity high
python log_analyzer.py auth.log --json > alerts.json
```

## Options

| Flag | Meaning |
|------|---------|
| `--min-severity {low,medium,high}` | Only report alerts at or above this level. |
| `--samples N` | Show up to N sample lines per alert (default 3). |
| `--json` | Emit machine-readable JSON instead of text. |

## What changed in this rewrite

- **Takes files as arguments** (one or more) instead of a hard-coded
  `system.log`.
- **Severity levels** on every rule, with a `--min-severity` filter.
- **JSON output** for piping into other tooling.
- Proper error handling and a non-zero exit code when a file can't be read.

## Extending

Add entries to `ALERT_RULES` in `log_analyzer.py`. Each rule is a regular
expression, a description, and a severity.
