import networkx as nx
import matplotlib.pyplot as plt
import re
from collections import defaultdict

# Sample iptables-like rule format (one per line):
# ACTION PROTOCOL SRC_IP DST_IP SRC_PORT DST_PORT
# e.g.:
# ACCEPT tcp 192.168.1.0/24 10.0.0.1 1024 80
# DROP udp 0.0.0.0/0 10.0.0.5 any any

RULE_PATTERN = re.compile(
    r'(?P<action>ACCEPT|DROP|REJECT)\s+'
    r'(?P<protocol>\w+)\s+'
    r'(?P<src_ip>\S+)\s+'
    r'(?P<dst_ip>\S+)\s+'
    r'(?P<src_port>\S+)\s+'
    r'(?P<dst_port>\S+)', re.IGNORECASE)

def parse_rules(file_path):
    rules = []
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = RULE_PATTERN.match(line)
            if match:
                rules.append(match.groupdict())
            else:
                print(f"Line {line_num} skipped: invalid format")
    return rules

def detect_conflicts(rules):
    # Simplified conflict detection:
    # Conflicts if same protocol, src/dst IP and ports, but different action.
    conflicts = []
    seen = defaultdict(list)  # key: tuple of params except action -> list of actions
    for idx, rule in enumerate(rules):
        key = (
            rule['protocol'].lower(),
            rule['src_ip'],
            rule['dst_ip'],
            rule['src_port'],
            rule['dst_port'],
        )
        actions = seen[key]
        if actions and rule['action'].upper() not in actions:
            conflicts.append((idx + 1, rule, actions))
        actions.append(rule['action'].upper())
    return conflicts

def build_graph(rules):
    G = nx.DiGraph()

    for i, rule in enumerate(rules, 1):
        node_label = f"Rule {i}\n{rule['action']} {rule['protocol']} {rule['src_ip']}->{rule['dst_ip']}:{rule['dst_port']}"
        G.add_node(i, label=node_label, action=rule['action'].upper())

    # Example edges: sequence flow
    for i in range(1, len(rules)):
        G.add_edge(i, i + 1)

    return G

def visualize_graph(G):
    pos = nx.spring_layout(G)
    colors = ['green' if G.nodes[n]['action'] == 'ACCEPT' else 'red' for n in G.nodes()]
    labels = nx.get_node_attributes(G, 'label')
    plt.figure(figsize=(12, 8))
    nx.draw(G, pos, labels=labels, node_color=colors, with_labels=True, node_size=2000, font_size=8)
    plt.title("Firewall Rules Visualization")
    plt.show()

def suggest_optimizations(rules):
    suggestions = []
    # Example: merge consecutive ACCEPT rules with same protocol and dst_ip
    i = 0
    while i < len(rules) - 1:
        r1, r2 = rules[i], rules[i+1]
        if (r1['action'] == r2['action'] == 'ACCEPT' and
            r1['protocol'] == r2['protocol'] and
            r1['dst_ip'] == r2['dst_ip']):
            suggestions.append(f"Consider merging Rule {i+1} and Rule {i+2}: similar ACCEPT rules")
            i += 2
        else:
            i += 1
    return suggestions

def main():
    rule_file = "firewall_rules.txt"  # Input your firewall rules here
    print(f"Parsing rules from {rule_file}...")
    rules = parse_rules(rule_file)
    print(f"Parsed {len(rules)} rules.")

    conflicts = detect_conflicts(rules)
    if conflicts:
        print("\nDetected Conflicts:")
        for line_num, rule, actions in conflicts:
            print(f" Rule {line_num}: {rule} conflicts with actions {actions}")
    else:
        print("\nNo conflicts detected.")

    suggestions = suggest_optimizations(rules)
    if suggestions:
        print("\nOptimization Suggestions:")
        for s in suggestions:
            print(" -", s)
    else:
        print("\nNo optimization suggestions.")

    G = build_graph(rules)
    visualize_graph(G)

if __name__ == "__main__":
    main()
