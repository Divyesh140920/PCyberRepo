import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES key (must be 16, 24, or 32 bytes)
AES_KEY = b'ThisIsA16ByteKey'

# Server config
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345

def decrypt_message(ciphertext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size).decode()

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded)

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            try:
                msg = decrypt_message(data)
                print(f"[{addr}] {msg}")
            except:
                print(f"[{addr}] Received corrupted data or failed decryption.")
    finally:
        conn.close()
        print(f"[DISCONNECTED] {addr} disconnected.")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    main()
