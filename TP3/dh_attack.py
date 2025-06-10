from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding 
import os

parameters = dh.generate_parameters(generator=2, key_size=512)

# Alice
alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

# Bob
bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

# Troca de chaves
alice_shared_key = alice_private_key.exchange(bob_public_key)
bob_shared_key = bob_private_key.exchange(alice_public_key)

# Derivação da chave 
def derive_key(shared_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits 
        salt=None,
        info=b'handshakedata'
    ).derive(shared_key)

alice_key = derive_key(alice_shared_key)
bob_key = derive_key(bob_shared_key)

assert alice_key == bob_key

# Função para adicionar padding aos dados
def pad_data(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    return padder.update(data) + padder.finalize()

# Função para remover padding dos dados
def unpad_data(padded_data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# Cifração AES-CBC com padding
def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = pad_data(plaintext)  # Aplicar padding antes de cifrar
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, iv

# Decifração AES-CBC com remoção de padding
def decrypt(key, ciphertext, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_data(padded_data)  # Remover padding após decifrar

# Exemplo de uso
message = b"OLA MENSAGEM DE TESTE" 
ciphertext, iv = encrypt(alice_key, message)
decrypted_message = decrypt(bob_key, ciphertext, iv)

print("Mensagem original:", message)
print("Cipher Text: ", ciphertext.hex())
print("Mensagem decifrada:", decrypted_message)
assert decrypted_message == message


# Ataque MITM com g = 1
def mitm_attack_g_1(p):
    # Alice envia p e g = 1
    g = 1

    # Bob recebe p e g, e envia ACK
    # Alice envia A = g^a mod p == 1
    A = 1

    # Bob envia B = g^b mod p == 1
    B = 1

    # Chave compartilhada será 1
    shared_key = 1

    # Derivação da chave
    key = derive_key(shared_key.to_bytes((shared_key.bit_length() + 7) // 8, byteorder='big'))

    # Agora o atacante pode interceptar e decifrar as mensagens
    return key

# Exemplo de uso
malicious_key = mitm_attack_g_1(parameters.parameter_numbers().p)
print("Chave derivada pelo atacante (g = 1):", malicious_key.hex())

# Ataque MITM com g = p
def mitm_attack_g_p(p):
    # Alice envia p e g = p
    g = p

    # Bob recebe p e g, e envia ACK
    # Alice envia A = g^a mod p == 0
    A = 0

    # Bob envia B = g^b mod p == 0
    B = 0

    # Chave compartilhada será 0
    shared_key = 0

    # Derivação da chave
    key = derive_key(shared_key.to_bytes((shared_key.bit_length() + 7) // 8, byteorder='big'))

    # Agora o atacante pode interceptar e decifrar as mensagens
    return key

# Exemplo de uso
malicious_key = mitm_attack_g_p(parameters.parameter_numbers().p)
print("Chave derivada pelo atacante (g = p):", malicious_key.hex())


# Ataque MITM com g = p - 1
def mitm_attack_g_p_minus_1(p):
    # Alice envia p e g = p - 1
    g = p - 1

    # Bob recebe p e g, e envia ACK
    # Alice envia A = g^a mod p = (p-1)^a mod p
    # Se a é par, A = 1; se a é ímpar, A = p - 1
    A = 1 if (alice_private_key.private_numbers().x % 2 == 0) else p - 1

    # Bob envia B = g^b mod p = (p-1)^b mod p
    # Se b é par, B = 1; se b é ímpar, B = p - 1
    B = 1 if (bob_private_key.private_numbers().x % 2 == 0) else p - 1

    # Chave compartilhada será 1 ou p - 1
    shared_key = 1 if (A == 1 and B == 1) else p - 1

    # Derivação da chave
    key = derive_key(shared_key.to_bytes((shared_key.bit_length() + 7) // 8, byteorder='big'))

    # Agora o atacante pode interceptar e decifrar as mensagens
    return key

# Exemplo de uso
malicious_key = mitm_attack_g_p_minus_1(parameters.parameter_numbers().p)
print("Chave derivada pelo atacante (g = p - 1):", malicious_key.hex())


# entao basicamente este ataque mostra que se um man in the middle se conseguir manipular o g e dado que os processos de geracao de chave (salt, lenght, into)
# sao conhecidos, entao ele consegue prever a chave e decifrar todas as mensagens passadas entre o bob e a alice