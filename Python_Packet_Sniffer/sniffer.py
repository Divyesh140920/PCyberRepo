from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from datetime import datetime

def process_packet(packet):
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    if IP in packet:
        ip_layer = packet[IP]
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else ip_layer.proto
        print(f"[{timestamp}] {ip_layer.src} → {ip_layer.dst} | Protocol: {proto}", end='')

        if DNS in packet:
            print(f" | DNS Query: {packet[DNS].qd.qname.decode()}", end='')

        if Raw in packet and TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            payload = packet[Raw].load.decode(errors='ignore')
            if "HTTP" in payload:
                print(" | HTTP Data", end='')
        
        print()

# Start sniffing (Ctrl+C to stop)
print("📡 Starting packet sniffer... (Ctrl+C to stop)")
sniff(filter="ip", prn=process_packet, store=0)
