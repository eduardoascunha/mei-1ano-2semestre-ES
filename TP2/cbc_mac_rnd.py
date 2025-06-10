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
    
    # random IV
    iv = os.urandom(16)  # 128 bits

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()

    # cifra
    # o modo cbc supostamente ja trata da cadeira automaticamente
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # retorna o ultimo bloco
    return iv, ciphertext[-16:]

# cria a tag para o ficheiro
def generate_tag(key_base64, file_path):
    key = base64.b64decode(key_base64)

    with open(file_path, 'rb') as f:
        message = f.read()

    iv, tag = cbc_mac(key, message)
    
    # leva o iv concatenado na tag 
    return base64.b64encode(iv + tag).decode()

# verifica a tag
def check_tag(key_base64, file_path, tag_base64):
    key = base64.b64decode(key_base64)
    combined_data = base64.b64decode(tag_base64)

    # separa o iv da tag
    iv = combined_data[:16]
    expected_tag = combined_data[16:]

    with open(file_path, 'rb') as f:
        message = f.read()

    # gera uma tag com base no iv recebido
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
    
    actual_ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    actual_tag = actual_ciphertext[-16:]

    # verifica a tag recebida e a suposta
    if actual_tag != expected_tag:
        raise InvalidTag("Invalid Tag")

def main():
    if len(sys.argv) < 3:
        print("Uso: (A chave é gerada automaticamente)")
        print("python3 cbc_mac_rnd.py \"tag\" <file>")
        print("python3 cbc_mac_rnd.py \"check\" <key> <file> <tag>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "tag":
        file_path = sys.argv[2]

        key_base64 = generate_aes_key()
        print(f"Generated Key (base64): {key_base64}")

        tag = generate_tag(key_base64, file_path)
        print(f"Generated Tag: {tag}")

    elif command == "check":
        if len(sys.argv) != 5:
            print("Usage for check: python3 cbc_mac_rnd.py check <key> <file> <tag>")
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
