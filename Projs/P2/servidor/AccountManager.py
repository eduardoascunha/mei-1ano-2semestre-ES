import os
from servidor.DBManager import DBManager
import threading
import base64
import bcrypt
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

class AccountManager:
    def __init__(self):
        load_dotenv()
        self.MAX_TENTATIVAS_LOGIN = int(os.getenv('MAX_TENTATIVAS_LOGIN'))
        self.tentativas_login = {}
        self.tentativas_lock = threading.Lock()
        self.TEMPO_BLOQUEIO_LOGIN = timedelta(minutes=int(os.getenv('TEMPO_BLOQUEIO_LOGIN'))) # tempo de bloqueio de login

    def email_existe(self, email):
        cursor = DBManager()
        if cursor.existe_email_db(email):
            return True
        return False

    def obter_email_por_id(self, user_id):
        cursor = DBManager()
        return cursor.obter_email_por_id_db(user_id)

    def criar_conta(self, email, senha, chave_publica_base64):
        try:
            # Gerar salt e hash da senha
            senha_bytes = senha.encode('utf-8')
            salt = bcrypt.gensalt()
            senha_hash = bcrypt.hashpw(senha_bytes, salt)
            
            cursor = DBManager()
            
            return cursor.criar_conta_db(email, senha_hash, chave_publica_base64)
        
        except:
            return {
                'status': 'erro',
                'mensagem': 'Formato de chave pública inválido'
            }
    

    def verificar_tentativas_login(self, email, ip):
        with self.tentativas_lock:  # Protege o dicionário de tentativas
            
            chave = f"{email}:{ip}"
            agora = datetime.now()
            
            if chave in self.tentativas_login:
                tentativas = self.tentativas_login[chave]
                tentativas = [t for t in tentativas if (agora - t) < self.TEMPO_BLOQUEIO_LOGIN]
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
        """verifica se o user pode dar login e tem as credenciais corretas"""
        try:
            # Verificar numero de tentativas e aplicar atraso
            tentativas = self.verificar_tentativas_login(email, ip)
            if tentativas >= self.MAX_TENTATIVAS_LOGIN:
                return {
                    'status': 'erro',
                    'mensagem': f'Excesso de tentativas de login.'
                }
            # elif tentativas > 0:
            #     # Atraso exponencial: 2^tentativas segundos
            #     # 1ª falha: 2 segundos
            #     # 2ª falha: 4 segundos
            #     # 3ª falha: bloqueio
            #     atraso = 2 ** tentativas
            #     time.sleep(atraso) # sv é multi-threaded

            cursor = DBManager()
            resultado = cursor.obter_id_senha_hash_db(email)

            if resultado:
                user_id, senha_hash_armazenada = resultado
                senha_hash_armazenada = senha_hash_armazenada.encode('utf-8')
                senha_bytes = senha.encode('utf-8')
                
                if bcrypt.checkpw(senha_bytes, senha_hash_armazenada):
                    
                    # Login bem-sucedido - limpar tentativas
                    chave = f"{email}:{ip}"
                    if chave in self.tentativas_login:
                        del self.tentativas_login[chave]

                    # ID do cofre do user
                    cofre_id = cursor.obter_cofreID_db(user_id)

                    return {
                        'status': 'sucesso',
                        'mensagem': 'Login realizado com sucesso',
                        'user': {
                            'id': str(user_id),
                            'cofre_id': str(cofre_id)
                        }
                    }
            
            # else: Registar tentativa falhada
            self.registar_tentativa_login(email, ip)

            return {
                'status': 'erro',
                'mensagem': f'Email ou senha inválidos.'
            }
        
        except Exception as e:
            print(f"Erro na verificação do user: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao verificar user'}

        
    def remover_conta(self, email, password):
        # verifica se o email existe
        if not self.email_existe(email):
            return {
                'status': 'erro',
                'mensagem': f'Email inválido.'
            }

        # verifica se o email e a pass batem certo
        cursor = DBManager()
        resultado = cursor.obter_id_senha_hash_db(email)

        # programacao defensiva apenas
        if not resultado:
            return {
                'status': 'erro',
                'mensagem': f'Email inválido.'
            }

        user_id_armazenado, senha_hash_armazenada = resultado
        senha_hash_armazenada = senha_hash_armazenada.encode('utf-8')
        senha_bytes = password.encode('utf-8')
        
        if not bcrypt.checkpw(senha_bytes, senha_hash_armazenada):
            return {
                'status': 'erro',
                'mensagem': f'Email ou senha inválidos.'
            }
        
        # verifica se o id associado a esse email esta coerente com o user id
        #if user_id != user_id_armazenado:
        #    return {
        #        'status': 'erro',
        #        'mensagem': f'Sessão Errada!'
        #    }

        # procede à eliminacao
        resultado_final = cursor.remover_conta_db(user_id_armazenado)
        return resultado_final
        
    def listar_conteudo_cofre(self, email):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            cofre_id = cursor.obter_cofreID_db(user_id)
        
            conteudo = cursor.listar_pastas_ficheiros_do_cofre_db(cofre_id)
            return conteudo

        except Exception as e:
            print(f"Erro ao listar conteúdo: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao listar conteúdo'}

    def criar_pasta(self, email, pasta_pai_id, nome):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            cofre_id = cursor.obter_cofreID_db(user_id)

            return cursor.criar_pasta_db(nome, cofre_id, pasta_pai_id)

        except Exception as e:
            print(f"Erro ao criar pasta: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao criar pasta'}
            
    def remover_pasta(self, email, pasta_id):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            cofre_id = cursor.obter_cofreID_db(user_id)

            cofre_id_da_pasta = cursor.obter_cofreID_from_pasta_db(pasta_id)

            if cofre_id != cofre_id_da_pasta:
                return {'status': 'erro', 'mensagem': 'Pasta não pertence ao cofre do user'}
            
            return cursor.remover_pasta_db(pasta_id)
        
        except Exception as e:
            print(f"Erro ao remover pasta: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao remover pasta'}

    def listar_conteudo_pasta(self, pasta_id):
        try:
            cursor = DBManager()
            return cursor.listar_pasta_db(pasta_id)

        except Exception as e:
            print(f"Erro ao listar conteúdo: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao listar conteúdo'}

    def upload_ficheiro(self, email, nome, conteudo, iv, tag, chave_cifrada, pasta_pai_id=None):
        try:
            MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 2097152))  # Default: 2 MB (2 * 1024 * 1024 bytes)

            # Verificar o tamanho do ficheiro
            file_size = len(conteudo)
            if file_size > MAX_FILE_SIZE:
                return {
                    'status': 'erro',
                    'mensagem': f'Tamanho do ficheiro excede o limite permitido de {MAX_FILE_SIZE} bytes.'
                }

            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            cofre_id = cursor.obter_cofreID_db(user_id)

            resposta = cursor.upload_ficheiro_db(
                nome,
                conteudo,
                iv,
                tag,
                chave_cifrada,
                pasta_pai_id,
                user_id,
                cofre_id
            )
            print(resposta)
            return resposta

        except Exception as e:
            print(f"Erro ao fazer upload do ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao fazer upload do ficheiro'}
        
    def remover_ficheiro(self, email, path_ficheiro):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            cofre_id = cursor.obter_cofreID_db(user_id)
            partes_path = path_ficheiro.strip('/').split('/')
            
            # Obter o nome do ficheiro e a pasta que o contém
            ficheiro_nome = partes_path[-1]
            pasta_id = None  # Pasta raiz por padrão
            
            if len(partes_path) > 1:
                # Obter o ID da pasta pai, se houver
                pasta_atual = None
                for pasta in partes_path[:-1]:
                    pasta_atual = cursor.obter_id_pasta_por_nome_e_parent(pasta, pasta_atual, cofre_id)
                    if pasta_atual is None:
                        raise Exception("Caminho inválido")
                pasta_id = pasta_atual

            ficheiro_id = cursor.obter_id_ficheiro_por_nome_e_parent(ficheiro_nome, pasta_id, cofre_id)

            if ficheiro_id is None:
                return {'status': 'erro', 'mensagem': 'Ficheiro não encontrado'}

            cofre_id_do_ficheiro = cursor.obter_cofreID_from_ficheiro_db(ficheiro_id)

            if cofre_id != cofre_id_do_ficheiro:
                return {'status': 'erro', 'mensagem': 'Ficheiro não pertence ao cofre do user'}
            
            return cursor.remover_ficheiro_db(ficheiro_id)
        
        except Exception as e:
            print(f"Erro ao remover ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao remover ficheiro'}
    
    def ler_ficheiro(self, email, ficheiro_id):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            permissao = cursor.verificar_permissao_user_ficheiro(user_id,ficheiro_id,0)

            if user_id is None:
                return {'status': 'erro', 'mensagem': 'Usuário não encontrado'}

            if permissao == 0:
                return {'status': 'erro', 'mensagem': 'Sem permissões para ler o ficheiro'}
            
            return cursor.ler_ficheiro_db(ficheiro_id, user_id)
        
        except Exception as e:
            print(f"Erro ao ler ficheiro 1: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao ler ficheiro'}

    def pedido_modificar_ficheiro(self, email, ficheiro_id):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            permissao = cursor.verificar_permissao_user_ficheiro(user_id,ficheiro_id,2)

            if permissao == 0:
                return {'status': 'erro', 'mensagem': 'Sem permissões para modificar o ficheiro'}
            
            return cursor.ler_ficheiro_db(ficheiro_id, user_id)
        
        except Exception as e:
            print(f"Erro ao modificar ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao modificar ficheiro'}
        
    def modificar_ficheiro(self, email, ficheiro_id, conteudo, iv, tag):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            
            return cursor.modificar_ficheiro_db(ficheiro_id, conteudo, iv, tag)
        
        except Exception as e:
            print(f"Erro ao modificar ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao modificar ficheiro'}
        
    def pedido_adicionar_ao_ficheiro(self, email, ficheiro_id):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            permissao = cursor.verificar_permissao_user_ficheiro(user_id,ficheiro_id,1)

            if permissao == 0:
                return {'status': 'erro', 'mensagem': 'Sem permissões para adicionar ao ficheiro'}
            
            return cursor.ler_ficheiro_db(ficheiro_id, user_id)
        
        except Exception as e:
            print(f"Erro ao adicionar ao ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao adicionar ao ficheiro'}
        
    def adicionar_ao_ficheiro(self, email, ficheiro_id, conteudo, iv, tag):
        try:
            cursor = DBManager()
            
            user_id = cursor.obter_id_from_email_db(email)
            
            return cursor.adicionar_ao_ficheiro_db(ficheiro_id, conteudo, iv, tag)
        
        except Exception as e:
            print(f"Erro ao adicionar ao ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao adicionar ao ficheiro'}
