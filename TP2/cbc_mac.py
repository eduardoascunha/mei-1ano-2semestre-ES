import sys
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# pra execao pedida
class InvalidTag(Exception):
    """Exception raised for invalid MAC tag."""
    pass


def generate_aes_key():
    key = os.urandom(16)  # 16 bytes = 128 bits
    return base64.b64encode(key).decode('utf-8')


def cbc_mac(key, message):
    
    # iv tudo 0
    iv = bytes(16)  # 128 bits

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # padding pra ser multiplo do blocksize
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()

    # cifra
    # o modo cbc supostamente ja trata da cadeira automaticamente
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # retorna o ultimo bloco
    return ciphertext[-16:]

# cria a tag para o ficheiro
def generate_tag(key_base64, file_path):

    key = base64.b64decode(key_base64)

    with open(file_path, 'rb') as f:
        message = f.read()

    tag = cbc_mac(key, message)
    return base64.b64encode(tag).decode()


def check_tag(key_base64, file_path, tag_base64):
   
    key = base64.b64decode(key_base64)
    expected_tag = base64.b64decode(tag_base64)

    with open(file_path, 'rb') as f:
        message = f.read()

    actual_tag = cbc_mac(key, message)

    if actual_tag != expected_tag:
        raise InvalidTag("Tag Invalida") # execao pedida

def main():
    if len(sys.argv) < 3:
        print("Uso: (A chave é gerada automaticamente)")
        print("python3 cbc_mac.py \"tag\" <file>")
        print("python3 cbc_mac.py \"check\" <key> <file> <tag>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "tag":
        file_path = sys.argv[2]
        
        key_base64 = generate_aes_key()
        print(f"Chave Gerada (base64): {key_base64}")  # imprime a key gerada

        tag = generate_tag(key_base64, file_path)
        print(f"Tag gerada: {tag}")

    elif command == "check":
        if len(sys.argv) != 5:
            print("Usage for check: python3 cbc_mac.py check <key> <file> <tag>")
            sys.exit(1)
        key_base64 = sys.argv[2]
        file_path = sys.argv[3]
        tag_base64 = sys.argv[4]
        try:
            check_tag(key_base64, file_path, tag_base64)
            print("Tag Válida")
        except InvalidTag as e:
            print(e)
            sys.exit(1)
    else:
        print("Invalid command. Use 'tag' or 'check'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
