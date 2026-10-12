"""Firewall rule visualizer and conflict detector.

Parses a simple iptables-like rule file, reports shadowing/conflicting rules
and merge opportunities, and renders the rule chain as a graph.

Rule format (one per line; `#` starts a comment):

    ACTION PROTOCOL SRC_IP DST_IP SRC_PORT DST_PORT
    ACCEPT tcp 192.168.1.0/24 10.0.0.1 1024 80
    DROP   udp 0.0.0.0/0      10.0.0.5 any  any

Usage:
    python firewall_rule_visualizer.py firewall_rules.txt
    python firewall_rule_visualizer.py firewall_rules.txt --output rules.png
    python firewall_rule_visualizer.py firewall_rules.txt --no-graph
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass

RULE_PATTERN = re.compile(
    r"(?P<action>ACCEPT|DROP|REJECT)\s+"
    r"(?P<protocol>\w+)\s+"
    r"(?P<src_ip>\S+)\s+"
    r"(?P<dst_ip>\S+)\s+"
    r"(?P<src_port>\S+)\s+"
    r"(?P<dst_port>\S+)",
    re.IGNORECASE,
)


@dataclass
class Rule:
    action: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str

    def match_key(self) -> tuple[str, ...]:
        return (
            self.protocol.lower(),
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
        )


def parse_rules(path: str) -> list[Rule]:
    rules: list[Rule] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            match = RULE_PATTERN.match(line)
            if match:
                rules.append(Rule(**{k: v for k, v in match.groupdict().items()}))
            else:
                print(f"line {line_number} skipped: invalid format", file=sys.stderr)
    return rules


def detect_conflicts(rules: list[Rule]) -> list[tuple[int, Rule, set[str]]]:
    """Find rules whose match criteria duplicate an earlier rule's but whose
    action differs — the later rule is shadowed and never takes effect."""
    conflicts: list[tuple[int, Rule, set[str]]] = []
    seen: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for index, rule in enumerate(rules, 1):
        key = rule.match_key()
        prior = seen[key]
        if prior and rule.action.upper() not in prior:
            conflicts.append((index, rule, set(prior)))
        prior.add(rule.action.upper())
    return conflicts


def suggest_merges(rules: list[Rule]) -> list[str]:
    suggestions: list[str] = []
    i = 0
    while i < len(rules) - 1:
        a, b = rules[i], rules[i + 1]
        if (
            a.action.upper() == b.action.upper() == "ACCEPT"
            and a.protocol.lower() == b.protocol.lower()
            and a.dst_ip == b.dst_ip
        ):
            suggestions.append(f"Rules {i + 1} and {i + 2} are similar ACCEPTs — consider merging.")
            i += 2
        else:
            i += 1
    return suggestions


def render_graph(rules: list[Rule], output: str | None) -> None:
    """Render the rule chain. Writes to ``output`` if given, else shows a window."""
    try:
        import matplotlib
        if output:
            matplotlib.use("Agg")  # headless backend for file output
        import matplotlib.pyplot as plt
        import networkx as nx
    except ImportError:
        print("graphing skipped: install networkx and matplotlib (see requirements.txt)", file=sys.stderr)
        return

    graph = nx.DiGraph()
    for i, rule in enumerate(rules, 1):
        label = f"Rule {i}\n{rule.action} {rule.protocol}\n{rule.src_ip}→{rule.dst_ip}:{rule.dst_port}"
        graph.add_node(i, label=label, action=rule.action.upper())
    for i in range(1, len(rules)):
        graph.add_edge(i, i + 1)

    color_for = {"ACCEPT": "#16a34a", "DROP": "#dc2626", "REJECT": "#f97316"}
    colors = [color_for.get(graph.nodes[n]["action"], "#6b7280") for n in graph.nodes]
    labels = nx.get_node_attributes(graph, "label")

    plt.figure(figsize=(12, 8))
    nx.draw(
        graph, nx.spring_layout(graph, seed=42), labels=labels,
        node_color=colors, with_labels=True, node_size=2600, font_size=8,
    )
    plt.title("Firewall Rule Chain")
    if output:
        plt.savefig(output, bbox_inches="tight", dpi=120)
        print(f"Graph written to {output}")
    else:
        plt.show()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("rule_file", help="path to the rules file")
    parser.add_argument("--output", help="save the graph to this image file instead of showing a window")
    parser.add_argument("--no-graph", action="store_true", help="skip graph rendering")
    args = parser.parse_args(argv)

    try:
        rules = parse_rules(args.rule_file)
    except FileNotFoundError:
        print(f"error: file not found: {args.rule_file}", file=sys.stderr)
        return 1
    print(f"Parsed {len(rules)} rule(s).")

    conflicts = detect_conflicts(rules)
    if conflicts:
        print("\nConflicts (shadowed rules):")
        for index, rule, prior in conflicts:
            print(f"  Rule {index} ({rule.action}) conflicts with earlier action(s) {sorted(prior)}")
    else:
        print("\nNo conflicts detected.")

    merges = suggest_merges(rules)
    if merges:
        print("\nOptimization suggestions:")
        for item in merges:
            print(f"  - {item}")

    if not args.no_graph and rules:
        render_graph(rules, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
