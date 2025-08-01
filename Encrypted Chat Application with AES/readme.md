# Encrypted Chat Application with AES

## Description
This project is a simple client-server chat application written in Python, demonstrating end-to-end encryption using AES symmetric encryption (ECB mode).

Messages sent from the client to the server are encrypted using AES before transmission, and the server decrypts the messages upon receipt. This ensures secure communication over an insecure network.

## Features
- Client-server architecture using Python sockets.
- AES symmetric encryption for message confidentiality.
- Uses `pycryptodome` library for cryptographic functions.
- Simple, text-based interface.

## Requirements
- Python 3.x
- `pycryptodome` library (`pip install pycryptodome`)

## Usage

### Server
1. Run the server script: python server.py
2. The server will listen for incoming connections.

### Client
1. Run the client script: python client.py
2. Type messages and send to the server.
3. Type `exit` to close the connection.

## Important Notes
- This example uses AES in ECB mode for simplicity, which is **not recommended for production use** due to security weaknesses. For real applications, use AES modes like CBC or GCM with proper IV handling.
- Both server and client must share the same AES key (`AES_KEY`).
