# Port Scanner with Banner Grabbing

## Description
This Python tool scans a target IP address for open TCP ports within a specified range and attempts to retrieve service banners. Banner grabbing helps identify the service running on open ports, which can be useful during network reconnaissance and vulnerability assessment.

The scanner uses multithreading to speed up the scanning process.

## Features
- Scans TCP ports in a configurable range (default: 1-1024)
- Retrieves service banners from open ports (when available)
- Uses multithreading for faster scanning
- Simple, easy to customize and extend

## Requirements
- Python 3.x

## Usage
1. Clone the repository or download the script.
2. Modify the `target`, `start_port`, and `end_port` variables in `port_scanner_banner.py` to fit your needs.
3. Run the script:
4. The script will output open ports and any banners retrieved.