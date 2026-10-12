# Firewall Rule Visualizer and Generator

Parses a simple iptables-like rule file, flags shadowed/conflicting rules and
merge opportunities, and renders the rule chain as a graph.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python firewall_rule_visualizer.py firewall_rules.txt               # analyze + show graph
python firewall_rule_visualizer.py firewall_rules.txt --output rules.png   # save graph to file
python firewall_rule_visualizer.py firewall_rules.txt --no-graph    # text analysis only
```

## Rule format

One rule per line; `#` starts a comment.

```
ACTION PROTOCOL SRC_IP DST_IP SRC_PORT DST_PORT
ACCEPT tcp 192.168.1.0/24 10.0.0.1 1024 80
DROP   udp 0.0.0.0/0      10.0.0.5 any  any
```

See `firewall_rules.txt` for a sample set (including a deliberate conflict).

## What changed in this rewrite

- **CLI** — the rule file is an argument, not a hard-coded name.
- **Headless-friendly** — `--output file.png` renders with the `Agg` backend,
  so it works over SSH or in CI where there is no display.
- **Graceful degradation** — if `networkx`/`matplotlib` aren't installed, the
  text analysis still runs and the graph step is skipped with a note.
- **Cleaner parsing** — inline comments are stripped, and rules are modelled
  as a dataclass rather than loose dicts.
