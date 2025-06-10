import requests
import base64
import os
import typer
import json
from dotenv import load_dotenv
import subprocess
import base64
import os
import argon2  
import json 
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
import urllib.parse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

class Cliente:
    def __init__(self):
        #self.base_url = "http://127.0.0.1:8000" # HTTP
        self.base_url = "https://127.0.0.1:8000" # HTTPS
        #self.cert_path = "misc/server.crt"       
        self.cert_path = "misc/certs/fullchain.pem"

        load_dotenv()
        self.app_user = os.getenv("APP_USER")
        self.token_path = os.path.join(os.getenv("TOKENS_PATH"), self.app_user, "tokens")
        self.key_path = os.path.join(os.getenv("TOKENS_PATH"), self.app_user, "tokens_key")
        self.cipher = Fernet(self._load_or_create_key())

        self.ca_cert_path = "misc/certs/ca.cert.pem"
        self.ca_cert = self.load_cert_ca()

    def load_cert_ca(self):
        """Carrega o certificado da CA"""
        try:
            with open(self.ca_cert_path, "rb") as f:
                ca_cert_pem = f.read()
            return x509.load_pem_x509_certificate(ca_cert_pem)
        except Exception as e:
            print(f"Erro ao carregar certificado da CA: {e}")
            return None

    def verificar_certificado(self, cert_pem_bytes, email_esperado=None):
        """Verifica se um certificado foi assinado pela CA e pertence ao utilizador correto"""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem_bytes)
            
            # Verificar se foi assinado pela CA
            ca_public_key = self.ca_cert.public_key()
            
            # Fix: Use the correct verification method for certificate signatures
            try:       
                signature_algorithm = cert.signature_algorithm_oid._name
                
                if 'sha256' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA256()
                elif 'sha1' in signature_algorithm.lower():
                    hash_algorithm = hashes.SHA1()
                else:
                    hash_algorithm = hashes.SHA256()  # Default fallback
                
                # Verify the certificate signature
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(),  # Add the padding algorithm
                    hash_algorithm  # Add the hash algorithm
                )
                
            except Exception as verify_error:
                raise Exception(f"Falha na verificação da assinatura: {verify_error}")
                
            # Verificar validade temporal
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                raise Exception("Certificado expirado ou ainda não válido")
            
            # VERIFICAR IDENTIDADE se fornecida
            if email_esperado:
                # Verificar no Subject
                subject_cn = None
                for attribute in cert.subject:
                    if attribute.oid == NameOID.COMMON_NAME:
                        subject_cn = attribute.value
                        break
                
                # Verificar no Subject Alternative Name
                san_emails = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    for name in san_ext.value:
                        if isinstance(name, x509.RFC822Name):
                            san_emails.append(name.value)
                except x509.ExtensionNotFound:
                    pass
                
                # Verificar se o email esperado está presente
                if email_esperado not in [subject_cn] + san_emails:
                    raise Exception(f"Certificado não pertence ao utilizador {email_esperado}")
            
            return True, cert
        except Exception as e:
            print(f"Erro na verificação do certificado: {e}")
            return False, None

    def _load_or_create_key(self):
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                return f.read()
        else:
            os.makedirs(os.path.dirname(self.key_path), exist_ok=True)

            key = Fernet.generate_key()
            # guarda a key com permissões restritas
            with open(self.key_path, "wb") as f:
                f.write(key)
            os.chmod(self.key_path, 0o600)  # apenas o user pode ler/escrever
            return key

    def _save_tokens(self, access_token, refresh_token=None):
        os.makedirs(os.path.dirname(self.token_path), exist_ok=True)
        
        tokens = {"access_token": access_token}
        if refresh_token:
            tokens["refresh_token"] = refresh_token
        data = json.dumps(tokens).encode()
        encrypted = self.cipher.encrypt(data)
        with open(self.token_path, "wb") as f:
            f.write(encrypted)
        os.chmod(self.token_path, 0o600) 

    def _load_tokens(self):
        try:
            if os.path.exists(self.token_path):
                with open(self.token_path, "rb") as f:
                    encrypted = f.read()
                    data = self.cipher.decrypt(encrypted)
                    ret = json.loads(data.decode())
                    return {
                        "refresh_token": ret.get("refresh_token"),
                        "access_token": ret.get("access_token")
                    }
        except Exception as e:
            raise Exception(f"Erro ao carregar tokens: {str(e)}")

    def _headers(self):
        tokens = self._load_tokens()
        if tokens:
            return {"Authorization": f"Bearer {tokens['access_token']}"}
        return {}

    def gerar_certificado_cliente(self, email):
        try:
            # 1) Geração do par de chaves
            chave = RSA.generate(2048)
            chave_privada = chave.export_key()
            chave_publica = chave.publickey().export_key()

            pasta_email = os.path.join(os.getcwd(), f"misc/{email}")
            os.makedirs(pasta_email, exist_ok=True)
            # Salva chave privada
            with open(os.path.join(pasta_email, "chave_privada.pem"), "wb") as f:
                f.write(chave_privada)
            # Salva chave pública
            with open(os.path.join(pasta_email, "chave_publica.pem"), "wb") as f:
                f.write(chave_publica)

            # 2) Prepara objeto cryptography para gerar CSR
            chave_privada_crypto = serialization.load_pem_private_key(
                chave_privada, password=None, backend=default_backend()
            )
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name(
                        [
                            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
                            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Portugal"),
                            x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CofreDigital"),
                            x509.NameAttribute(NameOID.COMMON_NAME, email),
                        ]
                    )
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.RFC822Name(email)]),
                    critical=False
                )
                .sign(chave_privada_crypto, hashes.SHA256())
            )
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            csr_base64 = base64.b64encode(csr_pem).decode("utf-8")

            # 3) Chama o CA script local (sem / inicial) e captura saída
            comando = [
                "python3",
                "misc/ca_assinar_cliente.py",
                "--csr-base64",
                csr_base64,
                "--email",
                email,
            ]
            resultado = subprocess.run(
                comando, capture_output=True, text=True
            )
            if resultado.returncode != 0:
                print("Erro ao chamar ca_assinar_cliente.py:")
                print(resultado.stderr)
                return None

            cert_base64 = resultado.stdout.strip()
            if not cert_base64:
                print("CA retornou saída vazia.")
                return None

            cert_pem = base64.b64decode(cert_base64.encode("utf-8"))
            with open(os.path.join(pasta_email, "certificado.pem"), "wb") as f:
                f.write(cert_pem)

            print("Certificado e chaves gerados com sucesso.")
            return cert_pem

        except Exception as e:
            print(f"Erro ao gerar certificado: {e}")
            return None


    def criar_conta(self, email, password):
        # gerar certificado do cliente
        certificado_pem = self.gerar_certificado_cliente(email)
        if not certificado_pem:
            print("Erro ao gerar certificado")
            return
            
        certificado_base64 = base64.b64encode(certificado_pem).decode('utf-8')

        dados = {
            "email": email,
            "password": password,
            "certificado": certificado_base64,  
        }
        resp = requests.post(f"{self.base_url}/criar_conta", json=dados, verify=self.cert_path) 
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def login(self, email, password):
        dados = {
            "username": email,
            "password": password,
        }
        resp = requests.post(f"{self.base_url}/login", data=dados, verify=self.cert_path)
        resposta = resp.json()

        if resposta.get("2fa_required"):
            print("2FA está ativo nesta conta.")
            code = input("Introduza o código 2FA da app: ")
            dados_2fa = {
                "email": email,
                "code": code
            }
            resp_2fa = requests.post(f"{self.base_url}/login/2fa", json=dados_2fa, verify=self.cert_path)
            resposta_2fa = resp_2fa.json()
            if not resposta_2fa.get('access_token'):
                print("Login falhou:", resposta_2fa)
                return
            print("\nLogin bem-sucedido!")
            self._save_tokens(resposta_2fa['access_token'], resposta_2fa['refresh_token'])
            return

        if not resposta.get('access_token'):
            print("Login falhou:", resposta)
            return

        print("\nLogin bem-sucedido!")
        self._save_tokens(resposta['access_token'], resposta['refresh_token'])

    def login_google(self):
        resp = requests.get(f"{self.base_url}/auth/google/login", verify=self.cert_path)
        auth_url = resp.json()["auth_url"]
        print(f"Abra este link no navegador e faça login:\n{auth_url}")

        returned_code = input("Cole o valor do parâmetro 'code' da URL de callback: ")
        decoded_code = urllib.parse.unquote(returned_code)
        
        token_resp = requests.post(
            f"{self.base_url}/auth/google/token",
            params={"code": decoded_code},
            verify=self.cert_path
        )
        #typer.echo(json.dumps(token_resp.json(), indent=2))
        
        if not token_resp.json().get('access_token') or not token_resp.json().get('refresh_token'):
            print("Login falhou:", token_resp.json())
            return
        
        token_acess = token_resp.json().get('access_token', {})
        token_refresh = token_resp.json().get('refresh_token', {})
        self._save_tokens(token_acess, token_refresh)
        print("\nLogin bem-sucedido!")

    def ativar_2fa(self):
        resp = requests.post(f"{self.base_url}/2fa", headers=self._headers(), verify=self.cert_path)
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def desativar_2fa(self):
        resp = requests.delete(f"{self.base_url}/2fa", headers=self._headers(), verify=self.cert_path)
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def remover_conta(self, email, password):
        print("\nATENÇÃO: Esta ação irá remover permanentemente sua conta e todos os seus ficheiros!")

        dados = {
            "email": email,
            "password": password,
        }
        resp = requests.post(f"{self.base_url}/remover_conta", json=dados, headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.remover_conta(email, password)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def logout(self):
        refresh_token = self._load_tokens()['refresh_token']
        resp = requests.post(f"{self.base_url}/logout", headers=self._headers(), json={"refresh_token": refresh_token}, verify=self.cert_path)

        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.logout()
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
            return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

        #self._save_tokens("null", "null")  # limpa os tokens

    def listar_conteudo_cofre(self):
        resp = requests.get(f"{self.base_url}/cofre", headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.listar_conteudo_cofre()
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def criar_pasta(self, nome, pasta_pai_id=None): 
        dados = {
            "nome": nome,
            "pasta_pai_id": pasta_pai_id,
        }
        resp = requests.post(f"{self.base_url}/pastas", json=dados, headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.criar_pasta(nome, pasta_pai_id)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def remover_pasta(self, pasta_path):
        resp = requests.delete(f"{self.base_url}/pastas/{pasta_path}", headers=self._headers(), verify=self.cert_path) # pasta id vai no url
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.remover_pasta(pasta_path, outro_user_email)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def listar_conteudo_pasta(self, pasta_id):
        resp = requests.get(f"{self.base_url}/pastas/{pasta_id}", headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.listar_conteudo_pasta(pasta_id)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def listar_recursos_com_permissao(self):
        resp = requests.get(f"{self.base_url}/permissoes", headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.listar_recursos_com_permissao()
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def logs(self):
        resp = requests.get(f"{self.base_url}/logs", headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.logs()
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        typer.echo(resposta)

    def conceder_permissao(self, email_user, recurso_id, tipo_recurso, nivel):
        if tipo_recurso == "ficheiro":
            chave_ficheiro = self.obter_chave_ficheiro(recurso_id)
            chave_ficheiro_cifrada = self.cifrar_chave_ficheiro(email_user, chave_ficheiro)
            chave_ficheiro_cifrada_base64 = base64.b64encode(chave_ficheiro_cifrada).decode('utf-8')

            resp = requests.post(f"{self.base_url}/permissoes", json={
                'outro_user_email': email_user,
                'recurso_id': recurso_id,
                'tipo_recurso': tipo_recurso,
                'chave_ficheiro_cifrada': chave_ficheiro_cifrada_base64,
                'nivel_acesso': nivel
            }, headers=self._headers(), verify=self.cert_path)
        
        else:
            resp = requests.post(f"{self.base_url}/permissoes", json={
                'outro_user_email': email_user,
                'recurso_id': recurso_id,
                'tipo_recurso': tipo_recurso,
                'nivel_acesso': nivel
            }, headers=self._headers(), verify=self.cert_path)

        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.conceder_permissao(email_user, recurso_id, tipo_recurso, nivel)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        typer.echo(resposta)

    def remover_permissao(self, email_user, recurso_id, tipo_recurso):
        resp = requests.delete(f"{self.base_url}/permissoes", json={
            'outro_user_email': email_user,
            'recurso_id': recurso_id,
            'tipo_recurso': tipo_recurso,
        }, headers=self._headers(), verify=self.cert_path)

        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.remover_permissao(email_user, recurso_id, tipo_recurso)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        typer.echo(resposta)

    def alterar_permissao(self, email_user, recurso_id, tipo_recurso, novo_nivel):
        resp = requests.put(f"{self.base_url}/permissoes", json={
            'outro_user_email': email_user,
            'recurso_id': recurso_id,
            'tipo_recurso': tipo_recurso,
            'nivel_acesso': novo_nivel
        }, headers=self._headers(), verify=self.cert_path)

        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.alterar_permissao(email_user, recurso_id, tipo_recurso, novo_nivel)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        typer.echo(resposta)

    def backup_google_drive(self):
        resp = requests.post(f"{self.base_url}/backup/google-drive", headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.backup_google_drive()
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        typer.echo(resposta_formatada)

    def get_backup_google_drive(self, filename):
        resp = requests.get(f"{self.base_url}/backup/google-drive", params={'nome': filename}, headers=self._headers(), verify=self.cert_path)
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.get_backup_google_drive(filename)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
        resposta = resp.json()
        resposta_formatada = json.dumps(resposta, indent=2)
        #typer.echo(resposta_formatada)

        if 'status' in resposta and resposta['status'] == 'sucesso':
            conteudo_cifrado = base64.b64decode(resposta.get("conteudo"))
            iv = base64.b64decode(resposta.get("iv"))
            tag = base64.b64decode(resposta.get("tag"))
            chave_ficheiro_cifrada = base64.b64decode(resposta.get("chave_cifrada"))
            
            # Decifrar a chave do ficheiro com a chave privada do dono
            chave_ficheiro = self.decifrar_chave_ficheiro(chave_ficheiro_cifrada, self.app_user)
            
            # Decifrar o conteúdo do ficheiro com a chave decifrada
            conteudo_decifrado = self.decifrar_ficheiro(conteudo_cifrado, chave_ficheiro, iv, tag)
            
            # Mostrar o conteúdo decifrado
            print(conteudo_decifrado.decode('utf-8'))
        else:
            print("Erro ao obter backup do Google Drive.")
            return


    # def alterar_permissao(self, email_user, recurso_id, tipo_recurso, novo_nivel):
    #     mensagem = {
    #         'comando': 'alterar_permissao',
    #         'user_id': self.user_atual['id'],
    #         'email_user': email_user,
    #         'recurso_id': recurso_id,
    #         'tipo_recurso': tipo_recurso,
    #         'novo_nivel': novo_nivel
    #     }
    #     return self.enviar_mensagem(mensagem)
    
    def refresh(self):
        tokens = self._load_tokens()
        if not tokens:
            typer.echo("Nenhum token encontrado. Faça login novamente.")
            return False
        
        resp = requests.post(f"{self.base_url}/refresh", json={"refresh_token": tokens['refresh_token']}, verify=self.cert_path)
        
        if resp.status_code == 200:
            resposta = resp.json()
            typer.echo("Token renovado.")
            self._save_tokens(resposta['access_token'], resposta['refresh_token'])
            return True

        else:
            return False

    def upload_ficheiro(self, email, path_ficheiro, pasta_pai_id=None):
        if not os.path.isfile(path_ficheiro):
            print("Ficheiro não encontrado.")
            return
        
        try:
            # Ler o ficheiro em modo binário
            with open(path_ficheiro, 'rb') as f:
                conteudo = f.read()
            
            # Gerar uma chave aleatória única para este ficheiro
            chave_ficheiro = self.gerar_chave_ficheiro()
            
            # Cifrar o conteúdo do ficheiro com a chave gerada
            conteudo_cifrado, iv, tag = self.cifrar_ficheiro(conteudo, chave_ficheiro)
            
            # Cifrar a chave do ficheiro com a chave pública do dono
            chave_ficheiro_cifrada = self.cifrar_chave_ficheiro(email, chave_ficheiro)
            
            # Converter os dados binários cifrados para base64
            conteudo_cifrado_base64 = base64.b64encode(conteudo_cifrado).decode('utf-8')
            iv_base64 = base64.b64encode(iv).decode('utf-8')
            tag_base64 = base64.b64encode(tag).decode('utf-8')
            chave_ficheiro_cifrada_base64 = base64.b64encode(chave_ficheiro_cifrada).decode('utf-8')
            
            # Preparar dados para enviar ao servidor
            dados = {
                "nome_ficheiro": os.path.basename(path_ficheiro),
                "pasta_pai_id": pasta_pai_id,
                "conteudo_cifrado": conteudo_cifrado_base64,
                "iv": iv_base64,
                "tag": tag_base64,
                "chave_cifrada": chave_ficheiro_cifrada_base64
            }
            
            resp = requests.post(f"{self.base_url}/ficheiros/upload", json=dados, headers=self._headers() , verify=self.cert_path)

            if resp.status_code == 401:
                if self.refresh():
                    # tenta de novo apos refresh bem-sucedido
                    return self.upload_ficheiro(email, path_ficheiro, pasta_pai_id)
                else:
                    typer.echo("Sessão expirada. Faça login novamente.")
                    return
            
            # Verificar se a resposta é válida e tem um código de status adequado
            if resp.status_code == 200 or resp.status_code == 201:
                resposta = resp.json()
                typer.echo(resposta)
                return resposta
            else:
                # Imprimir informações sobre o erro
                typer.echo(f"Erro na requisição: Status code {resp.status_code}")
                typer.echo(f"Resposta: {resp.text}")
                
        except requests.exceptions.RequestException as e:
            typer.echo(f"Erro na conexão com o servidor: {str(e)}")
        except json.JSONDecodeError:
            typer.echo(f"Erro: Resposta do servidor não é um JSON válido: {resp.text}")
        except Exception as e:
            typer.echo(f"Erro ao processar ficheiro: {str(e)}")

    def remover_ficheiro(self, path_ficheiro):
        resp = requests.delete(f"{self.base_url}/ficheiros/{path_ficheiro}/remover", headers=self._headers() , verify=self.cert_path)
        
        # Verificar se precisa renovar o token
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.remover_ficheiro(path_ficheiro)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
                
        resposta = resp.json()
        typer.echo(resposta)

    def ler_ficheiro(self, email, ficheiro_id):
        resp = requests.get(f"{self.base_url}/ficheiros/{ficheiro_id}/ler", headers=self._headers(), verify=self.cert_path)
        
        # Verificar se precisa renovar o token
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.ler_ficheiro(email, ficheiro_id)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
                
        resposta = resp.json()
        if resposta.get("status") == "sucesso":
            conteudo_cifrado = base64.b64decode(resposta.get("conteudo"))
            iv = base64.b64decode(resposta.get("iv"))
            tag = base64.b64decode(resposta.get("tag"))
            chave_ficheiro_cifrada = base64.b64decode(resposta.get("chave_cifrada"))
            
            # Decifrar a chave do ficheiro com a chave privada do dono
            chave_ficheiro = self.decifrar_chave_ficheiro(chave_ficheiro_cifrada, email)
            
            # Decifrar o conteúdo do ficheiro com a chave decifrada
            conteudo_decifrado = self.decifrar_ficheiro(conteudo_cifrado, chave_ficheiro, iv, tag)
            
            # Mostrar o conteúdo decifrado
            print(conteudo_decifrado.decode('utf-8'))
        else:
            typer.echo(resposta)

    def modificar_ficheiro(self, email, ficheiro_id):
        resp = requests.get(f"{self.base_url}/ficheiros/{ficheiro_id}/pedido-modificar", headers=self._headers(), verify=self.cert_path)
        
        # Verificar se precisa renovar o token
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.modificar_ficheiro(email, ficheiro_id)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
                
        resposta = resp.json()
        if resposta.get("status") == "sucesso":
            # Obter a chave do ficheiro
            conteudo_cifrado = base64.b64decode(resposta.get("conteudo"))
            iv = base64.b64decode(resposta.get("iv"))
            tag = base64.b64decode(resposta.get("tag"))
            chave_ficheiro_cifrada = base64.b64decode(resposta.get("chave_cifrada")) 
        else:
            typer.echo(resposta)
            return

        # Decifrar a chave do ficheiro e o ficheiro
        chave_ficheiro = self.decifrar_chave_ficheiro(chave_ficheiro_cifrada, email)
        conteudo_decifrado = self.decifrar_ficheiro(conteudo_cifrado, chave_ficheiro, iv, tag)
        
        # Permitir que o user edite o conteúdo no terminal usando vipe
        processo = subprocess.run(
            ['vipe'],  
            input=conteudo_decifrado.decode('utf-8'),  
            capture_output=True,  
            text=True  
        )            
        novo_conteudo = processo.stdout.encode() 

        # Cifrar o novo conteúdo e codificar em base64
        conteudo_cifrado, iv, tag = self.cifrar_ficheiro(novo_conteudo, chave_ficheiro)
        conteudo_cifrado_base64 = base64.b64encode(conteudo_cifrado).decode('utf-8')
        iv_base64 = base64.b64encode(iv).decode('utf-8')
        tag_base64 = base64.b64encode(tag).decode('utf-8')

        # Preparar dados para enviar ao servidor
        dados = {
            "recurso_id": ficheiro_id,
            "conteudo_cifrado": conteudo_cifrado_base64,
            "iv": iv_base64,
            "tag": tag_base64
        }
        
        resp = requests.put(f"{self.base_url}/ficheiros/{ficheiro_id}/modificar", json=dados, headers=self._headers(), verify=self.cert_path)
        
        # Verificar se precisa renovar o token novamente para a requisição PUT
        if resp.status_code == 401:
            if self.refresh():
                # Reconstruir dados para não perder as alterações
                dados = {
                    "recurso_id": ficheiro_id,
                    "conteudo_cifrado": conteudo_cifrado_base64,
                    "iv": iv_base64,
                    "tag": tag_base64
                }
                resp = requests.put(f"{self.base_url}/ficheiros/{ficheiro_id}/modificar", json=dados, headers=self._headers(), verify=self.cert_path)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
                
        resposta = resp.json()
        typer.echo(resposta)

    def adicionar_ao_ficheiro(self, email, ficheiro_id):
        resp = requests.get(f"{self.base_url}/ficheiros/{ficheiro_id}/pedido-adicionar", headers=self._headers(), verify=self.cert_path)
        
        # Verificar se precisa renovar o token
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.adicionar_ao_ficheiro(email, ficheiro_id)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
                
        resposta = resp.json()
        if resposta.get("status") == "sucesso":
            # Obter a chave do ficheiro
            conteudo_cifrado = base64.b64decode(resposta.get("conteudo"))
            iv = base64.b64decode(resposta.get("iv"))
            tag = base64.b64decode(resposta.get("tag"))
            chave_ficheiro_cifrada = base64.b64decode(resposta.get("chave_cifrada"))    
        else:
            typer.echo(resposta)
            return

        # Decifrar a chave do ficheiro e o ficheiro
        chave_ficheiro = self.decifrar_chave_ficheiro(chave_ficheiro_cifrada, email)
        conteudo_decifrado = self.decifrar_ficheiro(conteudo_cifrado, chave_ficheiro, iv, tag)

        # Solicitar ao user apenas o novo conteúdo a ser adicionado
        processo = subprocess.run(
            ['vipe'],
            input="",  # Começamos com um editor vazio para o novo conteúdo
            capture_output=True,
            text=True
        )
        
        novo_conteudo_adicional = processo.stdout.encode()  # O conteúdo adicional
        
        # Append: concatenar o conteúdo existente com o novo conteúdo
        conteudo_completo = conteudo_decifrado + novo_conteudo_adicional

        # Cifrar o novo conteúdo e codificar em base64
        conteudo_cifrado, iv, tag = self.cifrar_ficheiro(conteudo_completo, chave_ficheiro)
        conteudo_cifrado_base64 = base64.b64encode(conteudo_cifrado).decode('utf-8')
        iv_base64 = base64.b64encode(iv).decode('utf-8')
        tag_base64 = base64.b64encode(tag).decode('utf-8')

        # Preparar dados para enviar ao servidor
        dados = {
            "recurso_id": ficheiro_id,
            "conteudo_cifrado": conteudo_cifrado_base64,
            "iv": iv_base64,
            "tag": tag_base64
        }
        
        resp = requests.put(f"{self.base_url}/ficheiros/{ficheiro_id}/adicionar", json=dados, headers=self._headers(), verify=self.cert_path)
        
        # Verificar se precisa renovar o token novamente para a requisição POST
        if resp.status_code == 401:
            if self.refresh():
                # Reconstruir dados para não perder as alterações
                dados = {
                    "recurso_id": ficheiro_id,
                    "conteudo_cifrado": conteudo_cifrado_base64,
                    "iv": iv_base64,
                    "tag": tag_base64
                }
                resp = requests.post(f"{self.base_url}/ficheiros/{ficheiro_id}/adicionar", json=dados, headers=self._headers(), verify=self.cert_path)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return
                
        resposta = resp.json()
        typer.echo(resposta)

    ##########
    ## encrypt
    ##########

    #def gerar_par_chaves(self,email):
    #    chave = RSA.generate(2048)
    #    chave_privada = chave.export_key()
    #    chave_publica = chave.publickey().export_key()
    #    
    #    # Criar uma pasta com o nome do email, se não existir
    #    pasta_email = os.path.join(os.getcwd(), f"misc/{email}")
    #    os.makedirs(pasta_email, exist_ok=True)
    #    
    #    # Guardar chave privada na pasta do email
    #    with open(os.path.join(pasta_email, 'chave_privada.pem'), 'wb') as f:
    #        f.write(chave_privada)
    #    
    #    # Guardar chave pública na pasta do email
    #    with open(os.path.join(pasta_email, 'chave_publica.pem'), 'wb') as f:
    #        f.write(chave_publica)
    #
    #    print("Par de chaves gerado e salvo com sucesso.")
    #    return chave_publica


    def gerar_chave_ficheiro(self):
        """Gera uma chave forte usando Argon2."""
        chave = os.urandom(16)  # chave aleatória de 16 bytes
        
        # Criar um objeto Argon2
        hasher = argon2.PasswordHasher(
            time_cost=2,    # Tempo de computação (ajustável)
            memory_cost=65536,  # Memória usada (64MB)
            parallelism=2,   # Paralelismo
            hash_len=32      # Gera uma chave de 32 bytes
        )
        
        # Converter os bytes para string antes de fazer hash
        chave_str = chave.hex()  # ou outra forma de converter bytes para string
        
        # Gerar o hash (retorna uma string)
        hash_str = hasher.hash(chave_str)
        
        # Usar um algoritmo de hash para converter a string para bytes de comprimento fixo
        import hashlib
        hash_final = hashlib.sha256(hash_str.encode()).digest()
        
        return hash_final

    def cifrar_ficheiro(self, conteudo, chave_ficheiro):
        # Gerar um vetor de inicialização (IV) aleatório
        iv = os.urandom(12)
        
        # Criar um objeto de cifra AES em modo GCM
        cifra = AES.new(chave_ficheiro, AES.MODE_GCM, nonce=iv)
        
        # Cifrar o conteúdo
        conteudo_cifrado, tag = cifra.encrypt_and_digest(conteudo)
        
        # Retornar o conteúdo cifrado junto com os metadados necessários para decifrar
        return conteudo_cifrado, iv, tag
        

    #def obter_chave_publica(self, email_user):
    #    resp = requests.get(f"{self.base_url}/obter_chave_publica/{email_user}", headers=self._headers(), verify=self.cert_path)
    #    # Verificar se precisa renovar o token
    #    if resp.status_code == 401:
    #        if self.refresh():
    #            # tenta de novo apos refresh bem-sucedido
    #            return self.obter_chave_publica(email_user)
    #        else:
    #            typer.echo("Sessão expirada. Faça login novamente.")
    #            return None
    #    resposta = resp.json()
    #    if resposta['status'] == 'sucesso':
    #        chave_publica_base64 = resposta['chave_publica']
    #        chave_publica = base64.b64decode(chave_publica_base64)
    #        return chave_publica
    #    return None
    
    def obter_chave_publica(self, email_user):
        resp = requests.get(f"{self.base_url}/obter_certificado_utilizador/{email_user}", headers=self._headers(), verify=self.cert_path)
        # Verificar se precisa renovar o token
        if resp.status_code == 401:
            if self.refresh():
                # tenta de novo apos refresh bem-sucedido
                return self.obter_chave_publica(email_user)
            else:
                typer.echo("Sessão expirada. Faça login novamente.")
                return None
        resposta = resp.json()
        if resposta['status'] == 'sucesso':
            certificado_base64 = resposta['certificado']
            certificado_bytes = base64.b64decode(certificado_base64)
            
            valido, cert = self.verificar_certificado(certificado_bytes, email_user)
            if not valido:
                typer.echo("Certificado inválido ou expirado.")
                return None
            # Extrair a chave pública do certificado
            chave_publica = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return chave_publica

        
    def obter_chave_privada(self,email):
        caminho_chave_privada = os.path.join(f"misc/{email}", 'chave_privada.pem')
        with open(caminho_chave_privada, 'rb') as f:
            chave_privada_pem = f.read()
        chave_privada = RSA.import_key(chave_privada_pem)
        
        return chave_privada

    def cifrar_chave_ficheiro(self, email_user, chave_ficheiro):
        chave_publica_str = self.obter_chave_publica(email_user)
        # Importar a chave pública 
        chave_publica = RSA.import_key(chave_publica_str)
        
        # Cifrar a chave do ficheiro com a chave pública do user
        cifrador = PKCS1_OAEP.new(chave_publica)
        chave_cifrada = cifrador.encrypt(chave_ficheiro)
        return chave_cifrada

    def decifrar_chave_ficheiro(self, chave_ficheiro_cifrada, email):
        # Obter a chave privada do cliente
        chave_privada = self.obter_chave_privada(email)
        
        # Decifrar a chave do ficheiro com a chave privada
        decifrador = PKCS1_OAEP.new(chave_privada)
        chave_ficheiro = decifrador.decrypt(chave_ficheiro_cifrada)
        
        return chave_ficheiro

    def obter_chave_ficheiro(self, id_ficheiro):
        resp = requests.get(f"{self.base_url}/obter_chave_ficheiro/{id_ficheiro}", headers=self._headers(), verify=self.cert_path)
        resposta = resp.json()
        print(resposta)
        if resposta['status'] == 'sucesso' and 'conteudo' in resposta and 'email_autenticado' in resposta: 
            chave_ficheiro_cifrada = base64.b64decode(resposta['conteudo'])
            chave_ficheiro = self.decifrar_chave_ficheiro(chave_ficheiro_cifrada, resposta['email_autenticado'])  
            return chave_ficheiro
        else:
            raise Exception(f"Erro ao obter chave do ficheiro: {resposta['mensagem']}")

    def decifrar_ficheiro(self, conteudo_cifrado, chave_ficheiro, iv, tag):
        # Criar um objeto de cifra AES em modo GCM
        cifra = AES.new(chave_ficheiro, AES.MODE_GCM, nonce=iv)    
        # Decifrar o conteúdo
        conteudo_decifrado = cifra.decrypt_and_verify(conteudo_cifrado, tag)
        return conteudo_decifrado

