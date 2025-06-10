from cryptography.hazmat.primitives.ciphers import Cipher as CryptographyCipher, algorithms, modes
import os
from abc import ABC, abstractmethod
import random

class Cipher(ABC):
    @abstractmethod
    def keygen(self) -> bytes:
        pass
  
    @abstractmethod
    def enc(self, key: bytes, text: bytes) -> bytes:
        pass

    @abstractmethod
    def dec(self, key: bytes, criptotext: bytes) -> bytes:
        pass


class INDCPA_Adv(ABC):
    @abstractmethod
    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        pass

    @abstractmethod
    def guess(self, oracle: callable, criptotext: bytes) -> int:
        pass


def IND_CPA(C: Cipher, A: INDCPA_Adv) -> bool:
    k = C.keygen()
    enc_oracle = lambda ptxt: C.enc(k, ptxt)
    
    m0, m1 = A.choose(enc_oracle)
    assert len(m0) == len(m1), "As mensagens m0 e m1 devem ter o mesmo comprimento"
    
    b = random.randint(0, 1)
    c = C.enc(k, [m0, m1][b])
    
    b_prime = A.guess(enc_oracle, c)
    return b == b_prime


class ChaCha20Cipher(Cipher):
    def keygen(self) -> bytes:
        return os.urandom(32)  # Chave de 256 bits (32 bytes)
  
    def enc(self, key: bytes, text: bytes) -> bytes:
        nonce = os.urandom(16)  # Nonce de 128 bits (16 bytes)
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = CryptographyCipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        return nonce + encryptor.update(text) + encryptor.finalize()
   
    def dec(self, key: bytes, criptotext: bytes) -> bytes:
        nonce = criptotext[:16]  # Extrai os primeiros 16 bytes como nonce
        ciphertext = criptotext[16:]  # O restante é o texto cifrado
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = CryptographyCipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    

# adivinha aleatoriamente
class RandomAdversary(INDCPA_Adv):
    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        # Escolhe duas mensagens com o mesmo comprimento
        m0 = b"hello world"  
        m1 = b"goodbye wor"  
        return m0, m1
    
    def guess(self, oracle: callable, criptotext: bytes) -> int:
        return random.randint(0, 1)
    

cipher = ChaCha20Cipher()
adversary = RandomAdversary()

results = [IND_CPA(cipher, adversary) for _ in range(1000)]
advantage = 2 * abs(sum(results) / len(results) - 0.5)
print(f"Vantagem do adversário: {advantage}")