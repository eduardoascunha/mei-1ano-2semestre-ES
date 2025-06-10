import os
import random
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# AES key Global 
AES_KEY = None

def encryption_oracle():
    global AES_KEY
    
    # Gera a key se ainda não existir
    if AES_KEY is None:
        AES_KEY = os.urandom(16)
    
    strings = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]
    
    chosen_string = random.choice(strings)
    plaintext = base64.b64decode(chosen_string)
    #print(plaintext)
    
    # Pad the string out to the 16-byte AES block size
    padded_plaintext = pad(plaintext, 16)
    
    iv = bytes(16) # iv iniciado a 0
    #iv = os.urandom(16) # iv random

    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(iv),
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_plaintext)
    ciphertext += encryptor.finalize()
    
    return ciphertext, iv


def decryption_oracle(ciphertext, iv):
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(iv),
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    try:
        padded_plaintext = decryptor.update(ciphertext)
        padded_plaintext += decryptor.finalize()
    
    except Exception:
        return False
    
    # Check if the padding is valid
    return is_padding_valid(padded_plaintext)


# atribui padding
def pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

# cheka se o padding é valido
def is_padding_valid(padded_data, block_size=16):
    if not padded_data or len(padded_data) % block_size != 0:
        return False  # Padding should only be checked for full blocks
    
    padding_length = padded_data[-1]

    if padding_length == 0 or padding_length > block_size:
        return False

    # Check if the last padding_length bytes are all equal to padding_length
    expected_padding = bytes([padding_length] * padding_length)
    actual_padding = padded_data[-padding_length:]

    if actual_padding != expected_padding:
        return False
    
    #print(actual_padding.hex())

    return True


if __name__ == "__main__":
    ciphertext, iv = encryption_oracle()
    print("Ciphertext:", ciphertext.hex())
    print("Padding valid:", decryption_oracle(ciphertext, iv))