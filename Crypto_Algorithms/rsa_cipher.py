from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Key generation
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encryption and Decryption
def rsa_encrypt(public_key, plaintext):
    pub_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(private_key, encrypted):
    priv_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted))
    return decrypted.decode()

# Demo
if __name__ == "__main__":
    priv, pub = generate_keys()
    msg = "RSA encryption demo"
    enc = rsa_encrypt(pub, msg)
    dec = rsa_decrypt(priv, enc)

    print(f"Original: {msg}")
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")
