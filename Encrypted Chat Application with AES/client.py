import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

AES_KEY = b'ThisIsA16ByteKey'

SERVER_HOST = '127.0.0.1'  # Change to server IP
SERVER_PORT = 12345

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded)

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_HOST, SERVER_PORT))
    print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")

    try:
        while True:
            msg = input("You: ")
            if msg.lower() == "exit":
                break
            encrypted_msg = encrypt_message(msg)
            client.sendall(encrypted_msg)
    finally:
        client.close()
        print("Disconnected from server.")

if __name__ == "__main__":
    main()
