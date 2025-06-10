import os
import base64
import threading
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class Logger:
    def __init__(self, password: str, log_path: str):
        self.salt = b'\x13\x98\x88\xfa\xb4\xde'  
        self.fernet = self._gerar_fernet(password)
        self.log_lock = threading.Lock()
        self.log_file = log_path

    def _gerar_fernet(self, password: str):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=1000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def registar_log(self, ip, acao, status, email="Anonimo", detalhes=None):
        with self.log_lock:
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"[{timestamp}] {ip} - {email} - {acao} - {status}"
                if detalhes:
                    log_entry += f" - {detalhes}"
                log_entry += "\n"

                log_cifrado = self.fernet.encrypt(log_entry.encode('utf-8'))

                with open(self.log_file, 'ab') as f:
                    f.write(log_cifrado + b'\n')
            except Exception as e:
                print(f"Erro ao registar log: {e}")

    def ler_logs(self):
        try:
            with open(self.log_file, 'rb') as f:
                for linha in f:
                    try:
                        log_decifrado = self.fernet.decrypt(linha.strip())
                        print(log_decifrado.decode('utf-8'))
                    except Exception as e:
                        print(f"Erro ao decifrar log: {e}")
        except Exception as e:
            print(f"Erro ao ler logs: {e}")
