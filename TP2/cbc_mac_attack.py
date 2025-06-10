import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# cbc mac
def cbc_mac(key, iv, message):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    ct = encryptor.update(padded_data) + encryptor.finalize()

    return ct[-16:]

# cbc mac attack
def cbc_mac_attack(mensagem1, mensagem2, tag1, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(mensagem1) + padder.finalize()

    bloco1_mensagem2 = mensagem2[:16]
    bloco_forjado = bytes([tag1[i] ^ bloco1_mensagem2[i] for i in range(16)])

    mensagem_forjada = padded_data + bloco_forjado + mensagem2[16:]

    tag3 = cbc_mac(key, iv, mensagem_forjada) # usa a chave apenas pra verificacao

    return mensagem_forjada, tag3


def main():
    
    key = os.urandom(16)
    iv = bytes(16)

    mensagem1 = b"mensagem para teste 1"
    mensagem2 = b"mensagem de teste 2"

    tag1 = cbc_mac(key, iv, mensagem1)
    tag2 = cbc_mac(key, iv, mensagem2)

    mensagem_forjada, tag3 = cbc_mac_attack(mensagem1, mensagem2, tag1, key, iv)

    print(f"Mensagem 1: {mensagem1}")
    print(f"Tag 1: {tag1}")
    print(f"Mensagem 2: {mensagem2}")
    print(f"Tag 2: {tag2}")
    print(f"Mensagem Forjada: {mensagem_forjada}")
    print(f"Tag 3: {tag3}")

    assert tag2 == tag3
    # se a tag2 for igual a tag3 entao a mensagem forjada possui a mesma tag que a mensagem2 inicial

    print(f"Valid.")

if __name__ == "__main__":
    main()


