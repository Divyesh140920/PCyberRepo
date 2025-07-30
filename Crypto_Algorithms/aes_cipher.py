from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(key, encrypted):
    raw = base64.b64decode(encrypted)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct).decode())

# Demo
if __name__ == "__main__":
    key = get_random_bytes(16)
    msg = "Confidential Data"
    encrypted = aes_encrypt(key, msg)
    decrypted = aes_decrypt(key, encrypted)

    print(f"Original: {msg}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
