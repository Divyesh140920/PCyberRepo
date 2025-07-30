def caesar_encrypt(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Demo
if __name__ == "__main__":
    msg = "CyberSecurity123"
    shift = 3
    enc = caesar_encrypt(msg, shift)
    dec = caesar_decrypt(enc, shift)

    print(f"Original: {msg}")
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")
