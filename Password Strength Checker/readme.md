# Password Strength Checker

Scores a password out of 100 using length, character variety, and penalties
for predictable patterns (common passwords, repeated characters, keyboard and
alphabet sequences). Available as a CLI and a small Flask web page.

## Setup

```bash
pip install -r requirements.txt     # only needed for the web UI
```

## CLI

```bash
python checker.py                   # prompts, input hidden
python checker.py --password "correct horse battery staple"
```

## Web UI

```bash
python InterfaceApp.py
# open http://127.0.0.1:5000/
```

## What changed in this rewrite

- **Richer scoring** — a 0-100 score driven mainly by length, plus detection
  of repeats and sequences, rather than a coarse 0-6 tally.
- **Hidden CLI input** — the password is read with `getpass` so it is not
  echoed or saved to shell history by default.
- **Flask `debug=False`** — the original ran with `debug=True`, which exposes
  the Werkzeug interactive debugger (a remote-code-execution risk if the app
  is ever reachable beyond localhost). It now binds to localhost with debug
  off.

## Note

This is a heuristic for learning. For production password-strength estimation,
use a maintained library such as [`zxcvbn`](https://github.com/dropbox/zxcvbn),
and check candidate passwords against a breach corpus (e.g. the Have I Been
Pwned k-anonymity API).
