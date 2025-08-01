from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
import time

# Counters for each protocol
protocol_counts = defaultdict(int)

# Lock for thread-safe updates
lock = threading.Lock()

def packet_handler(packet):
    with lock:
        if packet.haslayer(TCP):
            protocol_counts['TCP'] += 1
        elif packet.haslayer(UDP):
            protocol_counts['UDP'] += 1
        elif packet.haslayer(ICMP):
            protocol_counts['ICMP'] += 1
        else:
            protocol_counts['Other'] += 1

def print_stats():
    while True:
        time.sleep(5)  # print stats every 5 seconds
        with lock:
            total = sum(protocol_counts.values())
            if total == 0:
                print("No packets captured yet...")
                continue

            print("\n=== Network Traffic Statistics ===")
            print(f"Total packets captured: {total}")
            for proto in ['TCP', 'UDP', 'ICMP', 'Other']:
                count = protocol_counts.get(proto, 0)
                percent = (count / total) * 100 if total > 0 else 0
                print(f"{proto}: {count} packets ({percent:.2f}%)")
            print("==================================")

def main():
    print("Starting network traffic capture... (Press Ctrl+C to stop)")
    stats_thread = threading.Thread(target=print_stats, daemon=True)
    stats_thread.start()

    # sniff on all interfaces, store=False to avoid memory buildup
    sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    main()
