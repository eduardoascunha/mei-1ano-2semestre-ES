import os
import random
from abc import ABC, abstractmethod

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
    def choose(self, oracle: callable):
        pass

    @abstractmethod
    def guess(self, oracle: callable, criptotext: bytes):
        pass

class IdentityCipher(Cipher):
    def keygen(self):
        return b''
   
    def enc(self, key: bytes, text: bytes):
        return text
   
    def dec(self, key: bytes, criptotext: bytes):
        return criptotext

class RandomAdversary(INDCPA_Adv):
    def choose(self, oracle: callable):
        msg1 = b'hello'
        msg2 = b'world'
        return msg1, msg2

    def guess(self, oracle: callable, criptotext: bytes):
        return random.choice([0, 1])


def IND_CPA(CipherClass, AdversaryClass):
    cipher = CipherClass()
    adversary = AdversaryClass()
    
    key = cipher.keygen()
    enc_oracle = lambda ptxt: cipher.enc(key, ptxt)
    
    m0, m1 = adversary.choose(enc_oracle)
    assert len(m0) == len(m1), "As mensagens devem ter o mesmo tamanho."
    
    b = random.randint(0, 1)
    c = cipher.enc(key, [m0, m1][b])
    
    b_guess = adversary.guess(enc_oracle, c)
    
    return b == b_guess

num_tests = 1000
successes = sum(IND_CPA(IdentityCipher, RandomAdversary) for _ in range(num_tests))

advantage = 2 * abs(successes / num_tests - 0.5)
print(f"Vantagem do adversário: {advantage}")

