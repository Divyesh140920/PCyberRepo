# Network Traffic Analyzer with Protocol Classification

## Description
A Python tool that captures live network packets and classifies them by protocol type: TCP, UDP, and ICMP. The tool provides real-time traffic statistics, giving insights into network usage patterns.

This analyzer can help network administrators and security analysts monitor traffic composition on their networks.

## Features
- Live packet capture using `scapy`.
- Classifies packets by protocol: TCP, UDP, ICMP, and others.
- Real-time summary printed every 5 seconds.
- Lightweight and easy to run.

## Requirements
- Python 3.x
- `scapy` library (`pip install scapy`)

## Usage
1. Run the script with administrator/root privileges (required for sniffing packets):
2. Watch the console output for real-time protocol statistics.
3. Press Ctrl+C to stop.

## Disclaimer
Run this tool only on networks where you have permission to capture traffic.