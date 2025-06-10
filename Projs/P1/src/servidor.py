# servidor.py
import socket
import json
import threading
import psycopg2
from psycopg2 import Error
import bcrypt
import ssl
import secrets
from datetime import datetime, timedelta
import re
import uuid
import os
import shutil
from enum import Enum
import base64
import time
from dotenv import load_dotenv
from logs import Logger
import sys

class NivelAcesso(Enum):
    READ = 'read'
    APPEND = 'append'
    WRITE = 'write'

class Servidor:
    def __init__(self):
        # Locks para recursos compartilhados
        self.sessoes_lock = threading.Lock()
        self.tentativas_lock = threading.Lock()
        self.log_lock = threading.Lock()
        self.requisicoes_por_ip_lock = threading.Lock()
        
        self.sessoes_ativas = {}
        self.inicializar_base_dados()
        self.configurar_servidor_ssl()
        self.MAX_TENTATIVAS = 3
        self.TEMPO_BLOQUEIO = timedelta(minutes=5) # tempo de bloqueio de login
        self.TEMPO_SESSAO = timedelta(minutes=10)  # tempo de expiracao de sessao
        self.tentativas_login = {}  # dict com as tentativas
        
        # logger
        self.logger = Logger(
            password=os.getenv('LOG_PASSWORD'),
            log_path=os.getenv('LOG_PATH')
        )
        
        # Proteção DDoS
        self.MAX_CONEXOES_POR_IP = 5
        self.MAX_REQUISICOES_POR_MINUTO = 30
        self.TEMPO_BLOQUEIO_DDOS = timedelta(minutes=10)
        self.conexoes_por_ip = {}  # {ip: quantidade}
        self.requisicoes_por_ip = {}  # {ip: [(timestamp, quantidade)]}
        
        print("Servidor iniciado. Aguardando conexões...")

    def validar_email(self, email):
        # regex pra validar o mail
        padrao = r'^[a-zA-Z0-9._]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(padrao, email) is not None

    def inicializar_base_dados(self):
        try:

            load_dotenv() 

            # Conectar ao PostgreSQL
            self.conexao = psycopg2.connect( # thread safe
                host=os.getenv('DB_HOST'),
                database=os.getenv('DB_NAME'),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD')
            )
            
            cursor = self.conexao.cursor() # previne sql injection
            
            criar_tabela = r"""
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    senha_hash VARCHAR(255) NOT NULL,
                    chave_publica TEXT NOT NULL,
                    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT email_valido CHECK (email ~* '^[A-Za-z0-9._]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
                )
            """
            cursor.execute(criar_tabela)
            self.conexao.commit()
            cursor.close()
            
        except (Exception, Error) as error:
            print(f"Erro ao conectar ao PostgreSQL: {error}")
            raise

    def email_existe(self, email):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE email = %s)", (email,))
        existe = cursor.fetchone()[0]
        cursor.close()
        return existe

    def obter_email_por_id(self, user_id):
        """Obtém o email do usuário a partir do ID"""
        try:
            cursor = self.conexao.cursor()
            cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
            resultado = cursor.fetchone()
            return resultado[0] if resultado else f"USER-ID:{user_id}"
        except Exception as e:
            print(f"Erro ao obter email: {e}")
            return f"USER-ID:{user_id}"
        finally:
            cursor.close()

    def criar_conta(self, email, senha, chave_publica_base64):
        try:
            if not self.validar_email(email):
                return {
                    'status': 'erro',
                    'mensagem': 'Email inválido'
                }

            try:
                chave_publica = base64.b64decode(chave_publica_base64)
            except:
                return {
                    'status': 'erro',
                    'mensagem': 'Formato de chave pública inválido'
                }

            # Gerar salt e hash da senha
            senha_bytes = senha.encode('utf-8')
            salt = bcrypt.gensalt()
            senha_hash = bcrypt.hashpw(senha_bytes, salt)
            
            cursor = self.conexao.cursor()
            
            # Criar user
            cursor.execute(
                "INSERT INTO users (email, senha_hash, chave_publica) VALUES (%s, %s, %s) RETURNING id",
                (email, senha_hash.decode('utf-8'), chave_publica_base64)
            )
            user_id = cursor.fetchone()[0]
            
            # Criar cofre automaticamente para o user
            cursor.execute(
                "INSERT INTO cofres (dono_id) VALUES (%s) RETURNING id",
                (user_id,)
            )
            cofre_id = cursor.fetchone()[0]
            
            self.conexao.commit()

            self.logger.registar_log("N/A", "CRIAR_CONTA", "SUCESSO", email)

            return {
                'status': 'sucesso',
                'mensagem': 'Conta e cofre pessoal criados com sucesso',
                'user': {
                    'id': str(user_id),
                    'cofre_id': str(cofre_id)
                }
            }
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao criar user: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao criar conta'}
        
    def remover_conta(self, email, senha):
        try:
            # verifica credenciais
            cursor = self.conexao.cursor()
            cursor.execute("SELECT id, senha_hash FROM users WHERE email = %s", (email,))
            resultado = cursor.fetchone()
            
            if not resultado:
                return {'status': 'erro', 'mensagem': 'user não encontrado'}
            
            user_id, senha_hash_armazenada = resultado
            senha_hash_armazenada = senha_hash_armazenada.encode('utf-8')
            senha_bytes = senha.encode('utf-8')
            
            if not bcrypt.checkpw(senha_bytes, senha_hash_armazenada):
                return {'status': 'erro', 'mensagem': 'Senha incorreta'}
            
            # cofre do user
            cursor.execute("SELECT id FROM cofres WHERE dono_id = %s", (user_id,))
            cofre_id = cursor.fetchone()[0]
            
            # remover todas as permissoes dos ficheiros do cofre
            cursor.execute(
                """
                DELETE FROM permissoes 
                WHERE recurso_id IN (
                    SELECT id FROM ficheiros WHERE cofre_id = %s
                )
                """,
                (cofre_id,)
            )
            
            # remover todas as permissoes das pastas do cofre
            cursor.execute(
                """
                DELETE FROM permissoes 
                WHERE recurso_id IN (
                    SELECT id FROM pastas WHERE cofre_id = %s
                )
                """,
                (cofre_id,)
            )
            
            # remover todas as permissões do proprio user
            cursor.execute("DELETE FROM permissoes WHERE user_id = %s", (user_id,))

            # remover as chaves de ficheiros associadas ao user
            cursor.execute("DELETE FROM chaves WHERE user_id = %s", (user_id,))
            
            # remover todos os ficheiros do cofre
            cursor.execute("DELETE FROM ficheiros WHERE cofre_id = %s", (cofre_id,))
            
            # remover todas as pastas do cofre
            cursor.execute("DELETE FROM pastas WHERE cofre_id = %s", (cofre_id,))
            
            # remover o cofre
            cursor.execute("DELETE FROM cofres WHERE id = %s", (cofre_id,))
            
            # remover o user
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            
            self.conexao.commit()
            self.logger.registar_log("N/A", "REMOVER_CONTA", "SUCESSO", email)
            
            return {
                'status': 'sucesso',
                'mensagem': 'Conta removida com sucesso'
            }
            
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao remover conta: {e}")
            self.logger.registar_log("N/A", "REMOVER_CONTA", "ERRO", email, str(e))
            return {'status': 'erro', 'mensagem': 'Erro ao remover conta'}
        
        finally:
            cursor.close()

    def verificar_tentativas_login(self, email, ip):
        with self.tentativas_lock:  # Protege o dicionário de tentativas
            chave = f"{email}:{ip}"
            agora = datetime.now()
            
            if chave in self.tentativas_login:
                tentativas = self.tentativas_login[chave]
                tentativas = [t for t in tentativas if (agora - t) < self.TEMPO_BLOQUEIO]
                if tentativas:
                    self.tentativas_login[chave] = tentativas
                else:
                    del self.tentativas_login[chave]
            
            return len(self.tentativas_login.get(chave, []))

    def registar_tentativa_login(self, email, ip):
        with self.tentativas_lock:  # Protege o dicionário de tentativas
            chave = f"{email}:{ip}"
            if chave not in self.tentativas_login:
                self.tentativas_login[chave] = []
            self.tentativas_login[chave].append(datetime.now())

    def verificar_user(self, email, senha, ip):
        try:
            if not self.validar_email(email):
                self.logger.registar_log(ip, "LOGIN", "ERRO", email, "Email inválido")
                return {
                    'status': 'erro',
                    'mensagem': 'Email inválido'
                }

            # Verificar número de tentativas e aplicar atraso
            tentativas = self.verificar_tentativas_login(email, ip)
            if tentativas >= self.MAX_TENTATIVAS:
                self.logger.registar_log(ip, "LOGIN", "ERRO", email, "Excesso de tentativas")
                return {
                    'status': 'erro',
                    'mensagem': f'Excesso de tentativas de login.'
                }
            elif tentativas > 0:
                # Atraso exponencial: 2^tentativas segundos
                # 1ª falha: 2 segundos
                # 2ª falha: 4 segundos
                # 3ª falha: bloqueio
                atraso = 2 ** tentativas
                time.sleep(atraso) # sv é multi-threaded

            cursor = self.conexao.cursor()
            cursor.execute("SELECT id, senha_hash FROM users WHERE email = %s", (email,))
            resultado = cursor.fetchone()
            cursor.close()

            if resultado:
                user_id, senha_hash_armazenada = resultado
                senha_hash_armazenada = senha_hash_armazenada.encode('utf-8')
                senha_bytes = senha.encode('utf-8')
                
                if bcrypt.checkpw(senha_bytes, senha_hash_armazenada):
                    self.logger.registar_log(ip, "LOGIN", "SUCESSO", email)
                    
                    # Login bem-sucedido - limpar tentativas
                    chave = f"{email}:{ip}"
                    if chave in self.tentativas_login:
                        del self.tentativas_login[chave]

                    # Buscar o ID do cofre do user
                    cursor = self.conexao.cursor()
                    cursor.execute("SELECT id FROM cofres WHERE dono_id = %s", (user_id,))
                    cofre_id = cursor.fetchone()[0]
                    cursor.close()

                    return {
                        'status': 'sucesso',
                        'mensagem': 'Login realizado com sucesso',
                        'user': {
                            'id': str(user_id),
                            'cofre_id': str(cofre_id)
                        }
                    }
            
            # Registrar tentativa falhada
            self.logger.registar_log(ip, "LOGIN", "ERRO", email, "Credenciais inválidas")
            self.registar_tentativa_login(email, ip)
            tentativas_restantes = self.MAX_TENTATIVAS - (tentativas + 1)
            
            return {
                'status': 'erro',
                'mensagem': f'Email ou senha inválidos.'
            }
        
        except Exception as e:
            print(f"Erro na verificação do user: {e}")
            self.logger.registar_log(ip, "ERRO_VERIFICAÇÃO", "ERRO", email, str(e))
            return {'status': 'erro', 'mensagem': 'Erro ao verificar user'}


    def verificar_dono_cofre(self, cofre_id, user_id):
        """Verifica se o user é dono do cofre"""
        try:
            try:
                cofre_id = str(uuid.UUID(str(cofre_id)))
            except ValueError:
                return False
                
            cursor = self.conexao.cursor()
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM cofres WHERE id = %s AND dono_id = %s)",
                    (cofre_id, user_id)
            )
            eh_dono = cursor.fetchone()[0]
            cursor.close()
            return eh_dono

        except Exception:
            return False

    def upload_ficheiro(self, cofre_id, nome_ficheiro, conteudo_base64, iv_base64, tag_base64, chave_cifrada_base64,  pasta_id, user_id):
        try:
            # Obter email do user para o log
            cursor = self.conexao.cursor()
            cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
            email = cursor.fetchone()[0]
            
            if not self.verificar_dono_cofre(cofre_id, user_id):
                self.logger.registar_log("N/A", "UPLOAD", "ERRO", email, f"Acesso negado ao cofre {cofre_id}")
                return {'status': 'erro', 'mensagem': 'Acesso negado ao cofre'}

            # Descodificar o conteúdo de base64 (só para verificar se é válido)
            try:
                conteudo = base64.b64decode(conteudo_base64)
            except:
                return {'status': 'erro', 'mensagem': 'Conteúdo do ficheiro inválido'}

            cursor = self.conexao.cursor()
            cursor.execute(
                """
                INSERT INTO ficheiros (nome, cofre_id, pasta_id, conteudo, iv, tag, tipo, tamanho)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, data_upload
                """,
                (nome_ficheiro, cofre_id, pasta_id, conteudo_base64, iv_base64, tag_base64, 'ficheiro', len(conteudo_base64))
            )
            
            ficheiro_id, data_upload = cursor.fetchone()

            # Armazenar a chave cifrada na tabela `chaves`
            cursor.execute(
                """
                INSERT INTO chaves (ficheiro_id, user_id, chave_cifrada)
                VALUES (%s, %s, %s)
                """,
                (ficheiro_id, user_id, chave_cifrada_base64)
            )

            self.conexao.commit()
            
            self.logger.registar_log("N/A", "UPLOAD_FICHEIRO", "SUCESSO", email, 
                              f"Ficheiro: {nome_ficheiro}, Cofre: {cofre_id}")
            return {
                'status': 'sucesso',
                'mensagem': 'Ficheiro enviado com sucesso',
                'ficheiro': {
                    'id': str(ficheiro_id),
                    'nome': nome_ficheiro,
                    'data_upload': data_upload.isoformat()
                }
            }
            
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro no upload: {e}")
            self.logger.registar_log("N/A", "UPLOAD", "ERRO", email, str(e))
            return {'status': 'erro', 'mensagem': 'Erro ao fazer upload do ficheiro'}
        finally:
            cursor.close()

    def configurar_servidor_ssl(self):
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.servidor.bind(('localhost', 5555))
        self.servidor.listen(5)

        # Configurar contexto SSL com TLS 1.3
        self.contexto_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.contexto_ssl.minimum_version = ssl.TLSVersion.TLSv1_3
        self.contexto_ssl.maximum_version = ssl.TLSVersion.TLSv1_3
        self.contexto_ssl.load_cert_chain('server.crt', 'server.key')
        
        # Configurações de segurança
        self.contexto_ssl.options |= (
            ssl.OP_NO_TLSv1 | 
            ssl.OP_NO_TLSv1_1 | 
            ssl.OP_NO_TLSv1_2 |
            ssl.OP_SINGLE_DH_USE |
            ssl.OP_SINGLE_ECDH_USE
        )
        self.contexto_ssl.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')

    def criar_sessao(self, cliente_ssl, endereco):
        with self.sessoes_lock:  # Protege o dicionário de sessões
            sessao_id = secrets.token_hex(16)
            self.sessoes_ativas[sessao_id] = {
                'endereco': endereco,
                'inicio': datetime.now(),
                'expiracao': datetime.now() + self.TEMPO_SESSAO,
                'cipher': cliente_ssl.cipher(),
                'tls_version': cliente_ssl.version(),
                'chave_sessao': secrets.token_hex(32)
            }
            return sessao_id

    def verificar_sessao(self, sessao_id):
        with self.sessoes_lock:  # Protege o dicionário de sessões
            if sessao_id not in self.sessoes_ativas:
                return False
            
            if datetime.now() > self.sessoes_ativas[sessao_id]['expiracao']:
                del self.sessoes_ativas[sessao_id]
                return False
            
            return True


    def criar_pasta(self, nome, cofre_id, pasta_pai_id, user_id):
        try:
            if pasta_pai_id != None:
                try:
                    pasta_pai_id = str(uuid.UUID(str(pasta_pai_id)))
                except ValueError:
                    return {
                        'status': 'erro',
                        'mensagem': 'ID de pasta pai inválido'
                    }
                    
            # Verificar se user é dono do cofre
            if not self.verificar_dono_cofre(cofre_id, user_id):
                return {'status': 'erro', 'mensagem': 'Acesso negado ao cofre'}

            cursor = self.conexao.cursor()
            cursor.execute(
                """
                INSERT INTO pastas (nome, cofre_id, pasta_pai_id)
                VALUES (%s, %s, %s)
                RETURNING id, data_criacao
                """,
                (nome, cofre_id, pasta_pai_id)
            )
            
            pasta_id, data_criacao = cursor.fetchone()
            self.conexao.commit()
            
            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "CRIAR_PASTA", "SUCESSO", email=email)
            
            return {
                'status': 'sucesso',
                'mensagem': 'Pasta criada com sucesso',
                'pasta': {
                    'id': str(pasta_id),
                    'nome': nome,
                    'data_criacao': data_criacao.isoformat()
                }
            }
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao criar pasta: {e}")
            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "CRIAR_PASTA", "ERRO", email=email)
            return {'status': 'erro', 'mensagem': 'Erro ao criar pasta'}

    def verificar_pasta(self, pasta_id, user_id):
        cursor = None
        try:
            try:
                pasta_id = str(uuid.UUID(str(pasta_id)))
            except ValueError:
                return {
                    'status': 'erro',
                    'mensagem': 'ID de pasta inválido'
                }
                
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT p.id, p.nome, p.cofre_id, c.dono_id
                FROM pastas p
                JOIN cofres c ON p.cofre_id = c.id
                WHERE p.id = %s
                """,
                (pasta_id,)
            )
            
            resultado = cursor.fetchone()
            
            if not resultado:
                return {
                    'status': 'erro',
                    'mensagem': 'Pasta não encontrada'
                }
            
            pasta_info = {
                'id': str(resultado[0]),
                'nome': resultado[1],
                'cofre_id': str(resultado[2])
            }
            
            # aqui vai ter de se ver as permissoes na base de dados
            # pra ja apenas verificar se o user é o dono do cofre/pasta
            if str(resultado[3]) == user_id:
                email = self.obter_email_por_id(user_id)
                self.logger.registar_log("N/A", "VERIFICAR_PASTA", "SUCESSO", email=email)
                return {
                    'status': 'sucesso',
                    'pasta': pasta_info
                }
            else:
                email = self.obter_email_por_id(user_id)
                self.logger.registar_log("N/A", "VERIFICAR_PASTA", "ERRO", email=email)
                return {
                    'status': 'erro',
                    'mensagem': 'Você não tem permissão para acessar esta pasta'
                }
            
        except Exception as e:
            print(f"Erro ao verificar pasta: {e}")
            return {
                'status': 'erro',
                'mensagem': 'Erro ao verificar pasta'
            }
        finally:
            if cursor:
                cursor.close()

    def verificar_permissao(self, user_id, recurso_id, tipo_recurso, nivel_minimo):
        """Verifica se o user tem pelo menos o nível de permissão especificado"""
        try:
            cursor = self.conexao.cursor()
            
            # Primeiro verifica se é o dono (donos têm todas as permissões)
            if tipo_recurso == 'ficheiro':
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM ficheiros a
                        JOIN cofres c ON a.cofre_id = c.id
                        WHERE a.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, user_id)
                )
            else:  # pasta
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM pastas p
                        JOIN cofres c ON p.cofre_id = c.id
                        WHERE p.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, user_id)
                )
            
            if cursor.fetchone()[0]:
                return True
            
            # se nao é dono, verifica permissões
            niveis = {
                NivelAcesso.READ: 0,
                NivelAcesso.APPEND: 1,
                NivelAcesso.WRITE: 2
            }
            
            cursor.execute(
                """
                SELECT nivel FROM permissoes
                WHERE user_id = %s AND recurso_id = %s AND tipo_recurso = %s
                """,
                (user_id, recurso_id, tipo_recurso)
            )
            
            resultado = cursor.fetchone()
            if not resultado:
                return False
            
            nivel_atual = NivelAcesso(resultado[0])
            return niveis[nivel_atual] >= niveis[nivel_minimo]
            
        finally:
            cursor.close()

    def conceder_permissao(self, dono_id, user, recurso_id, tipo_recurso, nivel, chave_ficheiro_cifrada):
        try:
            cursor = self.conexao.cursor()
            
            # verifica se o user que vai receber a permissão existe
            # e retorna o seu id
            cursor.execute(
                """
                SELECT id FROM users 
                WHERE email = %s
                """,
                (user,)
            )
            resultado = cursor.fetchone()
            
            if not resultado:
                return {
                    'status': 'erro',
                    'mensagem': 'user não encontrado'
                }
            
            user_id = resultado[0]
            
            # verifica se o recurso existe
            if tipo_recurso == 'ficheiro':
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM ficheiros 
                        WHERE id = %s
                    )
                    """,
                    (recurso_id,)
                )
            else:  # pasta
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM pastas 
                        WHERE id = %s
                    )
                    """,
                    (recurso_id,)
                )
            
            if not cursor.fetchone()[0]:
                return {
                    'status': 'erro',
                    'mensagem': f'{tipo_recurso.capitalize()} não encontrado'
                }

            # verifica se quem esta a conceder permissao é o dono
            if tipo_recurso == 'ficheiro':
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM ficheiros a
                        JOIN cofres c ON a.cofre_id = c.id
                        WHERE a.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, dono_id)
                )
            else:  # pasta
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM pastas p
                        JOIN cofres c ON p.cofre_id = c.id
                        WHERE p.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, dono_id)
                )
            
            if not cursor.fetchone()[0]:
                return {
                    'status': 'erro',
                    'mensagem': 'Apenas o dono pode conceder permissões'
                }

            # se chegou aqui, pode conceder a permissão
            cursor.execute(
                """
                INSERT INTO permissoes (user_id, recurso_id, tipo_recurso, nivel)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_id, recurso_id) 
                DO UPDATE SET nivel = EXCLUDED.nivel
                RETURNING id
                """,
                (user_id, recurso_id, tipo_recurso, nivel)
            )

            # Armazenar a chave cifrada na tabela `chaves`
            cursor.execute(
                """
                INSERT INTO chaves (ficheiro_id, user_id, chave_cifrada)
                VALUES (%s, %s, %s)
                """,
                (recurso_id, user_id, chave_ficheiro_cifrada)
            )
            
            self.conexao.commit()
            
            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "CONCEDER_PERMISSAO", "SUCESSO", email=email)
            return {
                'status': 'sucesso',
                'mensagem': f'Permissão {nivel} concedida com sucesso'
            }
            
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao conceder permissão: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao conceder permissão'}
        finally:
            cursor.close()

    def listar_conteudo(self, cofre_id, pasta_id, user_id):
        try:
            if not self.verificar_dono_cofre(cofre_id, user_id):
                return {'status': 'erro', 'mensagem': 'Acesso negado ao cofre'}

            cursor = self.conexao.cursor()
            
            # listar pastas
            cursor.execute(
                """
                SELECT id, nome, data_criacao
                FROM pastas
                WHERE cofre_id = %s AND pasta_pai_id IS NOT DISTINCT FROM %s
                ORDER BY nome
                """,
                (cofre_id, pasta_id)
            )
            
            pastas = [
                {
                    'id': str(p[0]),
                    'nome': p[1],
                    'tipo': 'pasta',
                    'data_criacao': p[2].isoformat()
                }
                for p in cursor.fetchall()
            ]
            
            # listar ficheiros
            cursor.execute(
                """
                SELECT id, nome, tamanho, data_upload
                FROM ficheiros
                WHERE cofre_id = %s AND pasta_id IS NOT DISTINCT FROM %s
                ORDER BY nome
                """,
                (cofre_id, pasta_id)
            )
            
            ficheiros = [
                {
                    'id': str(a[0]),
                    'nome': a[1],
                    'tipo': 'ficheiro',
                    'tamanho': a[2],
                    'data_upload': a[3].isoformat()
                }
                for a in cursor.fetchall()
            ]
        
            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "LISTAR_CONTEUDO", "SUCESSO", email=email)
            
            return {
                'status': 'sucesso',
                'conteudo': {
                    'pastas': pastas,
                    'ficheiros': ficheiros
                }
            }
        except Exception as e:
            print(f"Erro ao listar conteúdo: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao listar conteúdo'}

    def verificar_ddos(self, ip):
        """Verifica se o IP está a fazer demasiados requests"""
        with self.requisicoes_por_ip_lock:
            agora = datetime.now()
            
            # Limpar registos antigos
            if ip in self.requisicoes_por_ip:
                # Manter apenas registos do último minuto
                self.requisicoes_por_ip[ip] = [
                    (ts, qtd) for ts, qtd in self.requisicoes_por_ip[ip]
                    if agora - ts < timedelta(minutes=1)
                ]
                
                # Calcular total de requisições no último minuto
                total_requisicoes = sum(qtd for _, qtd in self.requisicoes_por_ip[ip])
                
                if total_requisicoes >= self.MAX_REQUISICOES_POR_MINUTO:
                    return True
            
                # Registar nova requisição
            if ip not in self.requisicoes_por_ip:
                self.requisicoes_por_ip[ip] = []
            self.requisicoes_por_ip[ip].append((agora, 1))
            
            return False

    def listar_permissoes(self, user_id): # lista os ficheiros e pastas aos quais o user tem acesso
        try:
            cursor = self.conexao.cursor()
            
            # listar permissoes de ficheiros
            cursor.execute(
                """
                SELECT 
                    a.id,
                    a.nome,
                    a.tipo,
                    a.tamanho,
                    a.data_upload,
                    perm.nivel,
                    u.email as dono_email
                FROM ficheiros a
                JOIN permissoes perm ON a.id = perm.recurso_id AND perm.tipo_recurso = 'ficheiro'
                JOIN cofres c ON a.cofre_id = c.id
                JOIN users u ON c.dono_id = u.id
                WHERE perm.user_id = %s
                ORDER BY a.nome
                """,
                (user_id,)
            )
            
            ficheiros = [
                {
                    'id': str(a[0]),
                    'nome': a[1],
                    'tipo': a[2],
                    'tamanho': a[3],
                    'data_upload': a[4].isoformat(),
                    'nivel_permissao': a[5],
                    'dono': a[6]
                }
                for a in cursor.fetchall()
            ]
            
            # listar permissoes de pastas
            cursor.execute(
                """
                SELECT 
                    p.id,
                    p.nome,
                    p.data_criacao,
                    perm.nivel,
                    u.email as dono_email
                FROM pastas p
                JOIN permissoes perm ON p.id = perm.recurso_id AND perm.tipo_recurso = 'pasta'
                JOIN cofres c ON p.cofre_id = c.id
                JOIN users u ON c.dono_id = u.id
                WHERE perm.user_id = %s
                ORDER BY p.nome
                """,
                (user_id,)
            )
            
            pastas = [
                {
                    'id': str(p[0]),
                    'nome': p[1],
                    'data_criacao': p[2].isoformat(),
                    'nivel_permissao': p[3],
                    'dono': p[4]
                }
                for p in cursor.fetchall()
            ]

            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "LISTAR_PERMISSOES", "SUCESSO", email=email)

            return {
                'status': 'sucesso',
                'conteudo': {
                    'pastas': pastas,
                    'ficheiros': ficheiros
                }
            }
        
        except Exception as e:
            print(f"Erro ao listar permissões: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao listar permissões'}
        
        finally:
            cursor.close()

    def remover_permissao(self, dono_id, user, recurso_id, tipo_recurso):
        try:
            cursor = self.conexao.cursor()
            
            # verifica se o user que vai ter a permissão removida existe
            # e retorna o seu id
            cursor.execute(
                """
                SELECT id FROM users 
                WHERE email = %s
                """,
                (user,)
            )
            resultado = cursor.fetchone()
            
            if not resultado:
                return {
                    'status': 'erro',
                    'mensagem': 'User não encontrado'
                }
            
            user_id = resultado[0]
            
            # verifica se o recurso existe
            if tipo_recurso == 'ficheiro':
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM ficheiros 
                        WHERE id = %s
                    )
                    """,
                    (recurso_id,)
                )
            else:  # pasta
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM pastas 
                        WHERE id = %s
                    )
                    """,
                    (recurso_id,)
                )
            
            if not cursor.fetchone()[0]:
                return {
                    'status': 'erro',
                    'mensagem': f'{tipo_recurso.capitalize()} não encontrado/a'
                }

            # verifica se quem está a remover permissão é o dono
            if tipo_recurso == 'ficheiro':
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM ficheiros a
                        JOIN cofres c ON a.cofre_id = c.id
                        WHERE a.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, dono_id)
                )
            else:  # pasta
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM pastas p
                        JOIN cofres c ON p.cofre_id = c.id
                        WHERE p.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, dono_id)
                )
            
            if not cursor.fetchone()[0]:
                return {
                    'status': 'erro',
                    'mensagem': 'Apenas o dono pode remover permissões'
                }

            # remove a permissão
            cursor.execute(
                """
                DELETE FROM permissoes 
                WHERE user_id = %s AND recurso_id = %s AND tipo_recurso = %s
                """,
                (user_id, recurso_id, tipo_recurso)
            )
            
            self.conexao.commit()
            
            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "REMOVER_PERMISSAO", "SUCESSO", email=email)

            return {
                'status': 'sucesso',
                'mensagem': 'Permissão removida com sucesso'
            }
            
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao remover permissão: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao remover permissão'}
        finally:
            cursor.close()

    def alterar_permissao(self, dono_id, user, recurso_id, tipo_recurso, novo_nivel):
        try:
            cursor = self.conexao.cursor()
            
            # verifica se o user que vai receber a permissão existe
            # e retorna o seu id
            cursor.execute(
                """
                SELECT id FROM users 
                WHERE email = %s
                """,
                (user,)
            )
            resultado = cursor.fetchone()
            
            if not resultado:
                return {
                    'status': 'erro',
                    'mensagem': 'User não encontrado'
                }
            
            user_id = resultado[0]
            
            # verifica se o recurso existe
            if tipo_recurso == 'ficheiro':
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM ficheiros 
                        WHERE id = %s
                    )
                    """,
                    (recurso_id,)
                )
            else:  # pasta
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM pastas 
                        WHERE id = %s
                    )
                    """,
                    (recurso_id,)
                )
            
            if not cursor.fetchone()[0]:
                return {
                    'status': 'erro',
                    'mensagem': f'{tipo_recurso.capitalize()} não encontrado'
                }

            # verifica se quem está a alterar permissao é o dono
            if tipo_recurso == 'ficheiro':
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM ficheiros a
                        JOIN cofres c ON a.cofre_id = c.id
                        WHERE a.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, dono_id)
                )
            else:  # pasta
                cursor.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM pastas p
                        JOIN cofres c ON p.cofre_id = c.id
                        WHERE p.id = %s AND c.dono_id = %s
                    )
                    """,
                    (recurso_id, dono_id)
                )
            
            if not cursor.fetchone()[0]:
                return {
                    'status': 'erro',
                    'mensagem': 'Apenas o dono pode alterar permissões'
                }

            # verifica se a permissao existe
            cursor.execute(
                """
                SELECT EXISTS(
                    SELECT 1 FROM permissoes 
                    WHERE user_id = %s AND recurso_id = %s AND tipo_recurso = %s
                )
                """,
                (user_id, recurso_id, tipo_recurso)
            )
            
            if not cursor.fetchone()[0]:
                return {
                    'status': 'erro',
                    'mensagem': 'Permissão não encontrada'
                }

            # altera a permissão
            cursor.execute(
                """
                UPDATE permissoes 
                SET nivel = %s
                WHERE user_id = %s AND recurso_id = %s AND tipo_recurso = %s
                """,
                (novo_nivel, user_id, recurso_id, tipo_recurso)
            )
            
            self.conexao.commit()
            
            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "ALTERAR_PERMISSAO", "SUCESSO", email=email)
            
            return {
                'status': 'sucesso',
                'mensagem': f'Permissão alterada para {novo_nivel} com sucesso'
            }
            
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao alterar permissão: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao alterar permissão'}
        
        finally:
            cursor.close()

    def obter_chave_publica (self, email_user):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT chave_publica FROM users
                WHERE email = %s
                """,
                (email_user,)
            )
            chave_publica = cursor.fetchone()[0]
            return {
                'status': 'sucesso',
                'conteudo': chave_publica
            }
        except Exception as e:
            print(f"Erro ao obter chave pública: {e}")
            return None
        finally:
            cursor.close()

    def obter_chave_ficheiro (self, user_id, ficheiro_id ):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT chave_cifrada FROM chaves
                WHERE user_id = %s AND ficheiro_id = %s
                """,
                (user_id, ficheiro_id)
            )
            chave_ficheiro = cursor.fetchone()[0]
            return {
                'status': 'sucesso',
                'conteudo': chave_ficheiro
            }
        except Exception as e:
            print(f"Erro ao obter chave do ficheiro: {e}")
            return None
        finally:
            cursor.close()

    def ler_ficheiro(self, user_id, ficheiro_id):
        try:
            cursor = self.conexao.cursor()
            
            # Verificar se o user tem permissão de leitura
            if not self.verificar_permissao(user_id, ficheiro_id, 'ficheiro', NivelAcesso.READ):
                email = self.obter_email_por_id(user_id)
                self.logger.registar_log("N/A", "LER_FICHEIRO", "ERRO", email=email)
                return {'status': 'erro', 'mensagem': 'Acesso negado ao ficheiro'}
            
            cursor.execute(
                """
                SELECT conteudo, iv, tag FROM ficheiros
                WHERE id = %s
                """,
                (ficheiro_id,)
            )
            conteudo, iv, tag = cursor.fetchone()

            cursor.execute(
                """
                SELECT chave_cifrada FROM chaves
                WHERE ficheiro_id = %s AND user_id = %s
                """,
                (ficheiro_id, user_id)
            )

            chave_ficheiro = cursor.fetchone()[0]

            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "LER_FICHEIRO", "SUCESSO", email=email)

            return {
                'status': 'sucesso',
                'conteudo_cifrado': conteudo,
                'iv': iv,
                'tag': tag,
                'chave_ficheiro': chave_ficheiro
            }
        except Exception as e:
            print(f"Erro ao ler ficheiro: {e}")
            return None
        finally:
            cursor.close()

    def pedido_modificar_ficheiro(self, user_id, ficheiro_id):
        try:
            cursor = self.conexao.cursor()
            
            # Verificar se o user tem permissão de escrita
            if not self.verificar_permissao(user_id, ficheiro_id, 'ficheiro', NivelAcesso.WRITE):
                email = self.obter_email_por_id(user_id)
                self.logger.registar_log("N/A", "MODIFICAR_CONTEUDO_FICHEIRO", "ERRO", email=email)
                return {'status': 'erro', 'mensagem': 'Acesso negado ao ficheiro'}
            
            cursor.execute(
                """
                SELECT conteudo, iv, tag FROM ficheiros
                WHERE id = %s
                """,
                (ficheiro_id,)
            )
            conteudo, iv, tag = cursor.fetchone()

            cursor.execute(
                """
                SELECT chave_cifrada FROM chaves
                WHERE ficheiro_id = %s AND user_id = %s
                """,
                (ficheiro_id, user_id)
            )

            chave_ficheiro = cursor.fetchone()[0]

            return {
                'status': 'sucesso',
                'conteudo_cifrado': conteudo,
                'iv': iv,
                'tag': tag,
                'chave_cifrada': chave_ficheiro
            }
        except Exception as e:
            print(f"Erro ao pedir modificar ficheiro: {e}")
            return None
        finally:
            cursor.close()

    def modificar_ficheiro(self, user_id, ficheiro_id, conteudo_cifrado, iv, tag):
        try:
            cursor = self.conexao.cursor()
            
            # Verificar se o user tem permissão de escrita
            if not self.verificar_permissao(user_id, ficheiro_id, 'ficheiro', NivelAcesso.WRITE):
                return {'status': 'erro', 'mensagem': 'Acesso negado ao ficheiro'}
            
            cursor.execute(
                """
                UPDATE ficheiros
                SET conteudo = %s, iv = %s, tag = %s
                WHERE id = %s
                """,
                (conteudo_cifrado, iv, tag, ficheiro_id)
            )
            
            self.conexao.commit()
            
            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "MODIFICAR_CONTEUDO_FICHEIRO", "SUCESSO", email=email)
            return {'status': 'sucesso', 'mensagem': 'Ficheiro modificado com sucesso'}
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao modificar ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao modificar ficheiro'}
        finally:
            cursor.close()

    def pedido_adicionar_conteudo_ficheiro(self, user_id, ficheiro_id):
        try:
            cursor = self.conexao.cursor()
            
            # Verificar se o user tem permissão de escrita
            if not self.verificar_permissao(user_id, ficheiro_id, 'ficheiro', NivelAcesso.APPEND):
                email = self.obter_email_por_id(user_id)
                self.logger.registar_log("N/A", "ADICIONAR_CONTEUDO_FICHEIRO", "ERRO", email=email)
                return {'status': 'erro', 'mensagem': 'Acesso negado ao ficheiro'}
            
            cursor.execute(
                """
                SELECT conteudo, iv, tag FROM ficheiros
                WHERE id = %s
                """,
                (ficheiro_id,)
            )
            conteudo, iv, tag = cursor.fetchone()

            cursor.execute(
                """
                SELECT chave_cifrada FROM chaves
                WHERE ficheiro_id = %s AND user_id = %s
                """,
                (ficheiro_id, user_id)
            )

            chave_ficheiro = cursor.fetchone()[0]
            
            return {
                'status': 'sucesso',
                'conteudo_cifrado': conteudo,
                'iv': iv,
                'tag': tag,
                'chave_cifrada': chave_ficheiro
            }
        except Exception as e:
            print(f"Erro ao pedir modificar ficheiro: {e}")
            return None
        finally:
            cursor.close()

    def adicionar_conteudo_ficheiro (self, user_id, ficheiro_id, conteudo_cifrado, iv, tag):
        try:
            cursor = self.conexao.cursor()
            
            # Verificar se o user tem permissão de append
            if not self.verificar_permissao(user_id, ficheiro_id, 'ficheiro', NivelAcesso.APPEND):
                return {'status': 'erro', 'mensagem': 'Acesso negado ao ficheiro'}
            
            cursor.execute(
                """
                UPDATE ficheiros
                SET conteudo = %s, iv = %s, tag = %s
                WHERE id = %s
                """,
                (conteudo_cifrado, iv, tag, ficheiro_id)
            )
            
            self.conexao.commit()

            email = self.obter_email_por_id(user_id)
            self.logger.registar_log("N/A", "ADICIONAR_CONTEUDO_FICHEIRO", "SUCESSO", email=email)

            return {'status': 'sucesso', 'mensagem': 'Ficheiro editado com sucesso'}
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao modificar ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao editar ficheiro'}
        finally:
            cursor.close()



    def handle_cliente(self, cliente_ssl, endereco):
        
        ip = endereco[0]
        
        with self.sessoes_lock:
            if ip in self.conexoes_por_ip:
                if self.conexoes_por_ip[ip] >= self.MAX_CONEXOES_POR_IP:
                    cliente_ssl.close()
                    return
                self.conexoes_por_ip[ip] += 1
            else:
                self.conexoes_por_ip[ip] = 1
        
        sessao_id = self.criar_sessao(cliente_ssl, endereco)
        print(f"\nNova sessão estabelecida:")
        print(f"ID Sessão: {sessao_id}")
        print(f"Endereço: {endereco}")
        print(f"Versão TLS: {cliente_ssl.version()}")
        print(f"Cipher: {cliente_ssl.cipher()}")
        print(f"Início: {self.sessoes_ativas[sessao_id]['inicio']}\n")

        try:
            while True:
                # Verificar taxa de requisições
                if self.verificar_ddos(ip):
                    resposta = {
                        'status': 'erro',
                        'mensagem': f'Muitas requisições. Tente novamente em alguns minutos.'
                    }
                    cliente_ssl.send(json.dumps(resposta).encode('utf-8'))
                    break

                dados = cliente_ssl.recv(4096).decode('utf-8')
                if not dados:
                    break
                
                try:
                    mensagem = json.loads(dados)
                    comando = mensagem.get('comando')
                    
                    # Se não for login ou criar conta, verifica se a sessão expirou
                    if comando not in ['criar_conta', 'login']:
                        if not self.verificar_sessao(sessao_id):
                            resposta = {
                                'status': 'erro',
                                'mensagem': 'Sessão expirada. Por favor, faça login novamente.',
                                'requer_login': True
                            }
                            cliente_ssl.send(json.dumps(resposta).encode('utf-8'))
                            continue

                    resposta = {'status': 'erro', 'mensagem': 'Comando inválido'}
                    
                    if comando == 'criar_conta':
                        email = mensagem.get('email')
                        senha = mensagem.get('senha')
                        chave_publica = mensagem.get('chave_publica')
                        
                        if not email or not senha or not chave_publica:
                            resposta = {'status': 'erro', 'mensagem': 'Dados incompletos'}
                        elif self.email_existe(email):
                            resposta = {'status': 'erro', 'mensagem': 'Email já registado'}
                        else:
                            resposta = self.criar_conta(email, senha, chave_publica)
                    
                    elif comando == 'login':
                        email = mensagem.get('email')
                        senha = mensagem.get('senha')
                        ip = mensagem.get('ip')
                        resposta = self.verificar_user(email, senha, ip)
                        
                        # Se o login foi bem sucedido, criar nova sessão
                        if resposta['status'] == 'sucesso':
                            sessao_id = self.criar_sessao(cliente_ssl, endereco)
                    
                    elif comando == 'remover_conta':
                        email = mensagem.get('email')
                        senha = mensagem.get('senha')
                        resposta = self.remover_conta(email, senha)
                    
                    elif comando == 'upload_ficheiro':
                        nome = mensagem.get('nome')
                        conteudo_cifrado_base64 = mensagem.get('conteudo_cifrado') 
                        iv_base64 = mensagem.get('iv')
                        tag_base64 = mensagem.get('tag')
                        chave_cifrada_base64 = mensagem.get('chave_cifrada')
                        cofre_id = mensagem.get('cofre_id')
                        pasta_id = mensagem.get('pasta_id')
                        user_id = mensagem.get('user_id')
                        
                        resposta = self.upload_ficheiro(
                            cofre_id, nome, conteudo_cifrado_base64, iv_base64, tag_base64, chave_cifrada_base64, pasta_id, user_id
                        )
                    
                    elif comando == 'criar_pasta':
                        nome = mensagem.get('nome')
                        cofre_id = mensagem.get('cofre_id')
                        pasta_pai_id = mensagem.get('pasta_pai_id')
                        user_id = mensagem.get('user_id')
                        resposta = self.criar_pasta(nome, cofre_id, pasta_pai_id, user_id)
                    
                    elif comando == 'listar_conteudo':
                        cofre_id = mensagem.get('cofre_id')
                        pasta_id = mensagem.get('pasta_id')
                        user_id = mensagem.get('user_id')
                        resposta = self.listar_conteudo(cofre_id, pasta_id, user_id)
                    
                    elif comando == 'verificar_pasta':
                        pasta_id = mensagem.get('pasta_id')
                        user_id = mensagem.get('user_id')
                        resposta = self.verificar_pasta(pasta_id, user_id)
                    
                    elif comando == 'conceder_permissao':
                        dono_id = mensagem.get('user_id')
                        user = mensagem.get('email_user') # é o email do user que vai receber a permissao
                        recurso_id = mensagem.get('recurso_id')
                        tipo_recurso = mensagem.get('tipo_recurso')
                        nivel = mensagem.get('nivel')
                        chave_ficheiro_cifrada = mensagem.get('chave_ficheiro_cifrada')
                        resposta = self.conceder_permissao(dono_id, user, recurso_id, tipo_recurso, nivel, chave_ficheiro_cifrada)
                    
                    elif comando == 'listar_permissoes':
                        user_id = mensagem.get('user_id')
                        resposta = self.listar_permissoes(user_id)
                    
                    elif comando == 'remover_permissao':
                        dono_id = mensagem.get('user_id')
                        user = mensagem.get('email_user')
                        recurso_id = mensagem.get('recurso_id')
                        tipo_recurso = mensagem.get('tipo_recurso')
                        resposta = self.remover_permissao(dono_id, user, recurso_id, tipo_recurso)
                    
                    elif comando == 'alterar_permissao':
                        dono_id = mensagem.get('user_id')
                        user = mensagem.get('email_user') 
                        recurso_id = mensagem.get('recurso_id')
                        tipo_recurso = mensagem.get('tipo_recurso')
                        novo_nivel = mensagem.get('novo_nivel')
                        resposta = self.alterar_permissao(dono_id, user, recurso_id, tipo_recurso, novo_nivel)

                    elif comando == 'obter_chave_publica':
                        user_email = mensagem.get('user_email')
                        resposta = self.obter_chave_publica(user_email)

                    elif comando == 'obter_chave_ficheiro':
                        id_user_pediu = mensagem.get('id_user_pediu')
                        id_ficheiro = mensagem.get('id_ficheiro')

                        resposta = self.obter_chave_ficheiro(id_user_pediu, id_ficheiro)
                    
                    elif comando == 'ler_ficheiro':
                        id_user = mensagem.get('user_id')
                        id_ficheiro = mensagem.get('ficheiro_id')

                        resposta = self.ler_ficheiro(id_user, id_ficheiro)

                    elif comando == 'pedido_modificar_conteudo_ficheiro':
                        id_user = mensagem.get('user_id')
                        id_ficheiro = mensagem.get('ficheiro_id')

                        resposta = self.pedido_modificar_ficheiro(id_user, id_ficheiro)

                    elif comando == 'modificar_conteudo_ficheiro':
                        id_ficheiro = mensagem.get('ficheiro_id')
                        conteudo_cifrado = mensagem.get('conteudo_cifrado')
                        iv = mensagem.get('iv')
                        tag = mensagem.get('tag')
                        user_id = mensagem.get('user_id')

                        resposta = self.modificar_ficheiro(user_id, id_ficheiro, conteudo_cifrado, iv, tag)

                    elif comando == 'pedido_adicionar_conteudo_ficheiro':
                        id_user = mensagem.get('user_id')
                        id_ficheiro = mensagem.get('ficheiro_id')

                        resposta = self.pedido_adicionar_conteudo_ficheiro(id_user, id_ficheiro)

                    elif comando == 'adicionar_conteudo_ficheiro':
                        id_ficheiro = mensagem.get('ficheiro_id')
                        conteudo_cifrado = mensagem.get('conteudo_cifrado')
                        iv = mensagem.get('iv')
                        tag = mensagem.get('tag')
                        user_id = mensagem.get('user_id')

                        resposta = self.adicionar_conteudo_ficheiro(user_id, id_ficheiro, conteudo_cifrado, iv, tag)
                        
                    
                    cliente_ssl.send(json.dumps(resposta).encode('utf-8'))
                        
                    
                except json.JSONDecodeError as e:
                    print(f"Erro ao decodificar JSON: {e}")
                    self.logger.registar_log("N/A", "ERRO_JSON", "ERRO", email="N/A")
                    resposta = {'status': 'erro', 'mensagem': 'Formato de mensagem inválido'}
                    cliente_ssl.send(json.dumps(resposta).encode('utf-8'))
            
        except Exception as e:
            print(f"Erro na conexão com {endereco}: {e}")
            self.logger.registar_log("N/A", "ERRO_CONEXÃO", "ERRO", email="N/A")
            
        finally:
            # Limpar conexão ao finalizar
            print(f"Encerrando sessão {sessao_id}")
            if ip in self.conexoes_por_ip:
                self.conexoes_por_ip[ip] -= 1
                if self.conexoes_por_ip[ip] <= 0:
                    del self.conexoes_por_ip[ip]
                self.logger.registar_log(ip, "DESCONEXÃO", "SUCESSO", email="N/A")
            cliente_ssl.close()

    def iniciar(self):
        while True:
            try:
                cliente, endereco = self.servidor.accept()
                print(f"\nConexão recebida de {endereco}")
                
                # Wrap com TLS
                cliente_ssl = self.contexto_ssl.wrap_socket(
                    cliente, 
                    server_side=True,
                    do_handshake_on_connect=True
                )
                
                # Criar thread para novo cliente
                thread = threading.Thread(
                    target=self.handle_cliente, 
                    args=(cliente_ssl, endereco)
                )
                thread.start()
            
            except Exception as e:
                print(f"Erro ao aceitar conexão: {e}")

    def __del__(self): 
        if hasattr(self, 'conexao'):
            self.conexao.close()


if __name__ == '__main__':

    args = sys.argv[1:] 

    if args and args[0] == 'ler_logs':
        try: 
            load_dotenv() 
            logger = Logger(password=os.getenv('LOG_PASSWORD'), log_path=os.getenv('LOG_PATH'))
            logger.ler_logs()
            exit(0)
            
        except Exception as e:
            print(f"Erro ao ler logs: {e}")
            exit(1)
    else:
        servidor = Servidor()
        servidor.iniciar()
