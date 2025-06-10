import socket
import json
import ssl
import base64
import os
from getpass import getpass
import argon2  
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import subprocess

class Cliente:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Configurar contexto SSL
        self.contexto_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.contexto_ssl.minimum_version = ssl.TLSVersion.TLSv1_3
        self.contexto_ssl.maximum_version = ssl.TLSVersion.TLSv1_3
        self.contexto_ssl.verify_mode = ssl.CERT_REQUIRED
        self.contexto_ssl.check_hostname = True
        self.contexto_ssl.load_verify_locations('server.crt')
        
        self.user_atual = None
        self.cofre_id = None
        
        self.cliente = self.contexto_ssl.wrap_socket(
            self.socket, 
            server_hostname='localhost'
        )
        self.cliente.connect(('localhost', 5555))
        
        print(f"\nCliente conectado:")
        print(f"Versão TLS: {self.cliente.version()}")
        print(f"Cipher: {self.cliente.cipher()}")
        print(f"Servidor verificado: {self.cliente.getpeercert() is not None}\n")

    def enviar_mensagem(self, mensagem):
        try:
            # Converter para JSON com encoding adequado
            mensagem_json = json.dumps(mensagem, ensure_ascii=False)
            # Enviar a mensagem
            self.cliente.send(mensagem_json.encode('utf-8'))
            # Receber a resposta
            resposta = self.cliente.recv(4096).decode('utf-8')
            return json.loads(resposta)
        except json.JSONDecodeError as e:
            return {'status': 'erro', 'mensagem': f'Erro no formato da mensagem: {str(e)}'}
        except Exception as e:
            return {'status': 'erro', 'mensagem': f'Erro de comunicação: {str(e)}'}

    def gerar_par_chaves(self, email):
        chave = RSA.generate(2048)
        chave_privada = chave.export_key()
        chave_publica = chave.publickey().export_key()
        
        # Criar uma pasta com o nome do email, se não existir
        pasta_email = os.path.join(os.getcwd(), email)
        os.makedirs(pasta_email, exist_ok=True)
        
        # Guardar chave privada na pasta do email
        with open(os.path.join(pasta_email, 'chave_privada.pem'), 'wb') as f:
            f.write(chave_privada)
        
        # Guardar chave pública na pasta do email
        with open(os.path.join(pasta_email, 'chave_publica.pem'), 'wb') as f:
            f.write(chave_publica)
    
        print("Par de chaves gerado e salvo com sucesso.")
        return chave_publica

    def criar_conta(self, email, senha):

        # Gerar um par de chaves RSA
        chave_publica = self.gerar_par_chaves(email)
        chave_publica_base64 = base64.b64encode(chave_publica).decode('utf-8')

        mensagem = {
            'comando': 'criar_conta',
            'email': email,
            'senha': senha,
            'chave_publica': chave_publica_base64
        }
        return self.enviar_mensagem(mensagem)

    def login(self, email, senha):
        mensagem = {
            'comando': 'login',
            'email': email,
            'senha': senha
        }
        resposta = self.enviar_mensagem(mensagem)
        
        if resposta['status'] == 'sucesso':
            resposta['user']['email'] = email
        
        return resposta

    def remover_conta(self, email, senha):
        print("\nATENÇÃO: Esta ação irá remover permanentemente sua conta e todos os seus ficheiros!")
        confirmacao = input("Digite \"CONFIRMAR\" para prosseguir: ")
        
        if confirmacao != "CONFIRMAR":
            return {'status': 'erro', 'mensagem': 'Operação cancelada'}
        
        if email != self.user_atual['email']:
            return {'status': 'erro', 'mensagem': 'Você não tem permissão para remover esta conta'}
        
        mensagem = {
            'comando': 'remover_conta',
            'email': email,
            'senha': senha
        }
        return self.enviar_mensagem(mensagem)

    def criar_pasta(self, nome, pasta_pai_id=None):
        mensagem = {
            'comando': 'criar_pasta',
            'nome': nome,
            'pasta_pai_id': pasta_pai_id,
            'cofre_id': self.cofre_id,
            'user_id': self.user_atual['id']
        }
        return self.enviar_mensagem(mensagem)

    def listar_conteudo(self, pasta_id=None):
        mensagem = {
            'comando': 'listar_conteudo',
            'pasta_id': pasta_id,
            'cofre_id': self.cofre_id,
            'user_id': self.user_atual['id']
        }
        return self.enviar_mensagem(mensagem)

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
    

    def obter_chave_publica(self, email_user):

        if email_user is None:
            email_user = self.user_atual['email']
            caminho_chave_publica = os.path.join(email_user, 'chave_publica.pem')
            with open(caminho_chave_publica, 'rb') as f:
                chave_publica_pem = f.read()
                return chave_publica_pem
        else:
            mensagem = {
                'comando': 'obter_chave_publica',
                'user_email': email_user
            }

            resposta = self.enviar_mensagem(mensagem)

            if resposta['status'] == 'sucesso' and 'conteudo' in resposta:
                return base64.b64decode(resposta['conteudo'])
            else:
                erro_msg = resposta.get('mensagem', 'Resposta inválida do servidor')
                raise Exception(f"Erro ao obter chave pública: {erro_msg}")
        
    def obter_chave_privada(self):

        email = self.user_atual['email']

        caminho_chave_privada = os.path.join(email, 'chave_privada.pem')
        with open(caminho_chave_privada, 'rb') as f:
            chave_privada_pem = f.read()

        chave_privada = RSA.import_key(chave_privada_pem)
        
        return chave_privada


    def cifrar_chave_ficheiro(self, chave_ficheiro, email_user=None):

        chave_publica_str = self.obter_chave_publica(email_user)

        # Importar a chave pública 
        chave_publica = RSA.import_key(chave_publica_str)
        
        # Cifrar a chave do ficheiro com a chave pública do user
        cifrador = PKCS1_OAEP.new(chave_publica)
        chave_cifrada = cifrador.encrypt(chave_ficheiro)

        return chave_cifrada
    
    def decifrar_chave_ficheiro(self, chave_ficheiro_cifrada):
        # Obter a chave privada do cliente
        chave_privada = self.obter_chave_privada()
        
        # Decifrar a chave do ficheiro com a chave privada
        decifrador = PKCS1_OAEP.new(chave_privada)
        chave_ficheiro = decifrador.decrypt(chave_ficheiro_cifrada)
        
        return chave_ficheiro
    
        
    def obter_chave_ficheiro(self, id_user_pediu, id_ficheiro):
        """Obtém a chave de um ficheiro."""
        mensagem = {
            'comando': 'obter_chave_ficheiro',
            'id_user_pediu': id_user_pediu,
            'id_ficheiro': id_ficheiro
        }
        
        resposta = self.enviar_mensagem(mensagem)

        if resposta['status'] == 'sucesso' and 'conteudo' in resposta: 
            chave_ficheiro_cifrada = base64.b64decode(resposta['conteudo'])
            chave_ficheiro = self.decifrar_chave_ficheiro(chave_ficheiro_cifrada)
            return chave_ficheiro
        else:
            raise Exception(f"Erro ao obter chave do ficheiro: {resposta['mensagem']}")


    def upload_ficheiro(self, nome, caminho, pasta_id=None):
        try:
            # Verificar se o ficheiro existe
            if not os.path.exists(caminho):
                return {'status': 'erro', 'mensagem': 'ficheiro não encontrado'}

            # Ler o ficheiro em modo binário
            with open(caminho, 'rb') as f:
                conteudo = f.read()
            
            # Gerar uma chave aleatória única para este ficheiro
            chave_ficheiro = self.gerar_chave_ficheiro()
            
            # Cifrar o conteúdo do ficheiro com a chave gerada
            conteudo_cifrado, iv, tag= self.cifrar_ficheiro(conteudo, chave_ficheiro)
            
            # Cifrar a chave do ficheiro com a chave pública do dono
            chave_ficheiro_cifrada = self.cifrar_chave_ficheiro(chave_ficheiro)
            
            # Converter os dados binários cifrados para base64
            conteudo_cifrado_base64 = base64.b64encode(conteudo_cifrado).decode('utf-8')
            iv_base64 = base64.b64encode(iv).decode('utf-8')
            tag_base64 = base64.b64encode(tag).decode('utf-8')
            chave_ficheiro_cifrada_base64 = base64.b64encode(chave_ficheiro_cifrada).decode('utf-8')
            
            # Construir a mensagem a enviar para o servidor
            mensagem = {
                'comando': 'upload_ficheiro',
                'nome': nome,
                'pasta_id': pasta_id,
                'cofre_id': self.cofre_id,
                'conteudo_cifrado': conteudo_cifrado_base64,
                'iv': iv_base64,
                'tag': tag_base64,
                'chave_cifrada': chave_ficheiro_cifrada_base64,
                'user_id': self.user_atual['id']
            }
            
            # Enviar a mensagem para o servidor
            return self.enviar_mensagem(mensagem)
        
        except Exception as e:
            return {'status': 'erro', 'mensagem': f'Erro ao processar ficheiro: {str(e)}'}
        
    def ler_ficheiro(self, ficheiro_id):
        try:
            # Solicitar o ficheiro ao servidor
            mensagem = {
                'comando': 'ler_ficheiro',
                'ficheiro_id': ficheiro_id,
                'user_id': self.user_atual['id']
            }
            
            resposta = self.enviar_mensagem(mensagem)

            if resposta['status'] != 'sucesso':
                return resposta
            
            # Extrair os dados do ficheiro recebido
            conteudo_cifrado = base64.b64decode(resposta['conteudo_cifrado'])
            iv = base64.b64decode(resposta['iv'])
            tag = base64.b64decode(resposta['tag'])
            chave_cifrada = base64.b64decode(resposta['chave_ficheiro'])
            
            # Decifrar a chave única do ficheiro usando a chave privada do cliente
            chave_ficheiro = self.decifrar_chave_ficheiro(chave_cifrada)
            
            # Decifrar o conteúdo do ficheiro usando a chave única
            cifra = AES.new(chave_ficheiro, AES.MODE_GCM, nonce=iv)
            try:
                conteudo_decifrado = cifra.decrypt_and_verify(conteudo_cifrado, tag)
            except ValueError as e:
                return {'status': 'erro', 'mensagem': 'Falha na verificação de integridade do ficheiro. O ficheiro pode ter sido corrompido ou adulterado.'}
            
            # Exibir conteúdo no terminal usando `less` (somente leitura)
            subprocess.run(['less'], input=conteudo_decifrado.decode('utf-8'), text=True)

            return {'status': 'sucesso', 'mensagem': 'Ficheiro exibido com sucesso'}
            
        except Exception as e:
            return {'status': 'erro', 'mensagem': f'Erro ao acessar ou decifrar ficheiro: {str(e)}'}
        
    
    def modificar_conteudo_ficheiro(self, ficheiro_id):
        try:
            # Solicitar o ficheiro ao servidor
            mensagem = {
                'comando': 'pedido_modificar_conteudo_ficheiro',
                'ficheiro_id': ficheiro_id,
                'user_id': self.user_atual['id']
            }
            
            resposta = self.enviar_mensagem(mensagem)
            
            if resposta['status'] != 'sucesso':
                return resposta
            
            # Extrair os dados do ficheiro recebido
            conteudo_cifrado = base64.b64decode(resposta['conteudo_cifrado'])
            iv = base64.b64decode(resposta['iv'])
            tag = base64.b64decode(resposta['tag'])
            chave_cifrada = base64.b64decode(resposta['chave_cifrada'])
            
            # Decifrar a chave única do ficheiro usando a chave privada do cliente
            chave_ficheiro = self.decifrar_chave_ficheiro(chave_cifrada)
            
            # Decifrar o conteúdo do ficheiro usando a chave única
            cifra = AES.new(chave_ficheiro, AES.MODE_GCM, nonce=iv)
            try:
                conteudo_decifrado = cifra.decrypt_and_verify(conteudo_cifrado, tag)
            except ValueError as e:
                return {'status': 'erro', 'mensagem': 'Falha na verificação de integridade do ficheiro. O ficheiro pode ter sido corrompido ou adulterado.'}
            


            # Permitir que o user edite o conteúdo no terminal usando vipe
            processo = subprocess.run(
                ['vipe'],  
                input=conteudo_decifrado.decode('utf-8'),  
                capture_output=True,  
                text=True  
            )
            
            novo_conteudo = processo.stdout.encode()  # O novo conteúdo editado

            # Substituir o conteúdo existente com o novo conteúdo
            conteudo_cifrado, iv, tag = self.cifrar_ficheiro(novo_conteudo, chave_ficheiro)
            # Codificar em base64
            conteudo_cifrado_base64 = base64.b64encode(conteudo_cifrado).decode('utf-8')
            iv_base64 = base64.b64encode(iv).decode('utf-8')
            tag_base64 = base64.b64encode(tag).decode('utf-8')
            # Enviar a mensagem para o servidor
            mensagem = {
                'comando': 'modificar_conteudo_ficheiro',
                'ficheiro_id': ficheiro_id,
                'conteudo_cifrado': conteudo_cifrado_base64,
                'iv': iv_base64,
                'tag': tag_base64,
                'user_id': self.user_atual['id']
            }
            
            return self.enviar_mensagem(mensagem)
            
        except Exception as e:
            return {'status': 'erro', 'mensagem': f'Erro ao adicionar conteúdo ao ficheiro: {str(e)}'}

        
    
    def adicionar_conteudo_ficheiro(self, ficheiro_id):
        try:
           # Solicitar o ficheiro ao servidor
            mensagem = {
                'comando': 'pedido_adicionar_conteudo_ficheiro',
                'ficheiro_id': ficheiro_id,
                'user_id': self.user_atual['id']
            }
            
            resposta = self.enviar_mensagem(mensagem)
            
            if resposta['status'] != 'sucesso':
                return resposta
            
            # Extrair os dados do ficheiro recebido
            conteudo_cifrado = base64.b64decode(resposta['conteudo_cifrado'])
            iv = base64.b64decode(resposta['iv'])
            tag = base64.b64decode(resposta['tag'])
            chave_cifrada = base64.b64decode(resposta['chave_cifrada'])
            
            # Decifrar a chave única do ficheiro usando a chave privada do cliente
            chave_ficheiro = self.decifrar_chave_ficheiro(chave_cifrada)
            
            # Decifrar o conteúdo do ficheiro usando a chave única
            cifra = AES.new(chave_ficheiro, AES.MODE_GCM, nonce=iv)
            try:
                conteudo_decifrado = cifra.decrypt_and_verify(conteudo_cifrado, tag)
            except ValueError as e:
                return {'status': 'erro', 'mensagem': 'Falha na verificação de integridade do ficheiro. O ficheiro pode ter sido corrompido ou adulterado.'}
            
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
            
            # Cifrar o conteúdo completo
            conteudo_cifrado, iv, tag = self.cifrar_ficheiro(conteudo_completo, chave_ficheiro)
                
            # Codificar em base64
            conteudo_cifrado_base64 = base64.b64encode(conteudo_cifrado).decode('utf-8')
            iv_base64 = base64.b64encode(iv).decode('utf-8')
            tag_base64 = base64.b64encode(tag).decode('utf-8')
            
            # Enviar a mensagem para o servidor
            mensagem = {
                'comando': 'adicionar_conteudo_ficheiro',
                'ficheiro_id': ficheiro_id,
                'conteudo_cifrado': conteudo_cifrado_base64,
                'iv': iv_base64,
                'tag': tag_base64,
                'user_id': self.user_atual['id']
            }
            
            return self.enviar_mensagem(mensagem)
            
        except Exception as e:
            return {'status': 'erro', 'mensagem': f'Erro ao adicionar conteúdo ao ficheiro: {str(e)}'}

    def conceder_permissao(self, email_user, recurso_id, tipo_recurso, nivel):

        chave_ficheiro = self.obter_chave_ficheiro(self.user_atual['id'], recurso_id)
        chave_ficheiro_cifrada = self.cifrar_chave_ficheiro(chave_ficheiro, email_user)
        chave_ficheiro_cifrada_base64 = base64.b64encode(chave_ficheiro_cifrada).decode('utf-8')

        mensagem = {
            'comando': 'conceder_permissao',
            'email_user': email_user,
            'recurso_id': recurso_id,
            'tipo_recurso': tipo_recurso,
            'nivel': nivel,
            'chave_ficheiro_cifrada': chave_ficheiro_cifrada_base64,
            'user_id': self.user_atual['id']
        }
        return self.enviar_mensagem(mensagem)

    def remover_permissao(self, email_user, recurso_id, tipo_recurso):
        mensagem = {
            'comando': 'remover_permissao',
            'user_id': self.user_atual['id'],
            'email_user': email_user,
            'recurso_id': recurso_id,
            'tipo_recurso': tipo_recurso
        }
        return self.enviar_mensagem(mensagem)

    def alterar_permissao(self, email_user, recurso_id, tipo_recurso, novo_nivel):
        mensagem = {
            'comando': 'alterar_permissao',
            'user_id': self.user_atual['id'],
            'email_user': email_user,
            'recurso_id': recurso_id,
            'tipo_recurso': tipo_recurso,
            'novo_nivel': novo_nivel
        }
        return self.enviar_mensagem(mensagem)

def menu_pasta(cliente, pasta_id):
    pasta_pai = []

    while True:
        print("\n=========MENU PASTA=========")
        print("Gerenciar Pasta:")
        print("1. Listar conteúdo")
        print("2. Criar nova pasta")
        print("3. Upload ficheiro")
        print("4. Gerenciar permissões")
        print("5. Entrar numa pasta")
        print("6. Voltar para pasta pai")
        print("7. Voltar ao menu principal")
        
        opcao = input("Escolha uma opção: ")
        
        if opcao == '1':
            resposta = cliente.listar_conteudo(pasta_id)
            if resposta['status'] == 'sucesso':
                if not resposta['conteudo']['pastas'] and not resposta['conteudo']['ficheiros']:
                    print("\nA pasta está vazia!")
                else:
                    if resposta['conteudo']['pastas']:
                        print("\nPastas:")
                        for pasta in resposta['conteudo']['pastas']:
                            print(f"Nome: {pasta['nome']}")
                            print(f"ID: {pasta['id']}")
                            print("---")
                    if resposta['conteudo']['ficheiros']:
                        print("\nficheiros:")
                        for ficheiro in resposta['conteudo']['ficheiros']:
                            print(f"ID: {ficheiro['id']}")
                            print(f"Nome: {ficheiro['nome']}")
                            print(f"Tamanho: {ficheiro['tamanho']} bytes")
                            print(f"Data: {ficheiro['data_upload']}")
                            print("---")
            else:
                print(resposta['mensagem'])
        
        elif opcao == '2':
            nome = input("Digite o nome da nova pasta: ")
            resposta = cliente.criar_pasta(nome, pasta_id)
            print(resposta['mensagem'])
        
        elif opcao == '3':
            nome = input("Digite o nome do ficheiro: ")
            caminho = input("Digite o caminho do ficheiro: ")
            resposta = cliente.upload_ficheiro(nome, caminho, pasta_id)
            print(resposta['mensagem'])
        
        elif opcao == '4':
            recurso_id = input("Digite o ID do recurso: ")
            tipo = input("Digite o tipo (ficheiro/pasta): ")
            if tipo != "ficheiro" and tipo != "pasta":
                print("Tipo inválido")
                continue
        
            email = input("Digite o email do utilizador a quem quer conceder permissão: ")
            print("Níveis de permissão disponíveis:")
            print("1. read")
            print("2. append")
            print("3. write")
            nivel = input("Escolha o nível de permissão (1-3): ")
            niveis = ['read', 'append', 'write']
            if nivel.isdigit() and 1 <= int(nivel) <= 3:
                resposta = cliente.conceder_permissao(
                    email, recurso_id, tipo, niveis[int(nivel)-1]
                )
                print(resposta['mensagem'])
            else:
                print("Nível inválido")
                continue
        
        elif opcao == '5':

            pasta_id_novo = input("Digite o ID da pasta que deseja entrar: ")
            # Envia comando para o servidor verificar a pasta

            if pasta_id_novo == pasta_id:
                print("Você já está nessa pasta")
                continue

            mensagem = {
                'comando': 'verificar_pasta',
                'pasta_id': pasta_id_novo,
                'user_id': cliente.user_atual['id']
            }
            resposta = cliente.enviar_mensagem(mensagem)
            
            if resposta['status'] == 'sucesso':
                pasta_pai.append(pasta_id)
                pasta_id = pasta_id_novo
                print(f"Entrou na pasta: {pasta_id_novo}")
                continue
            else:
                print(f"Erro: {resposta['mensagem']}")

        elif opcao == '6':
            if pasta_pai != []:
                pasta_id = pasta_pai.pop()
                print(f"Entrou na pasta {pasta_pai[-1] if pasta_pai else "Raiz"}")
                continue
            else:
                print("Não há pasta pai!")
                
        elif opcao == '7':
            print("A regressar ao menu principal...")
            break

def menu_principal(cliente):
    while True:
        print("\n=========MENU PRINCIPAL=========")
        print("Menu Principal:")
        print("1. Listar conteúdo do cofre")
        print("2. Criar nova pasta")
        print("3. Upload ficheiro")
        print("4. Gerenciar permissões")
        print("5. Entrar numa pasta")
        print("6. Listar recursos com permissão")
        print("7. Ler ficheiro (read)")
        print("8. Modificar ficheiro (write)")
        print("9. Adicionar conteúdo ao ficheiro (append)")
        print("10. Logout")
        print("11. Remover conta")
        
        opcao = input("Escolha uma opção: ")
        
        if opcao == '1':
            resposta = cliente.listar_conteudo()
            if resposta['status'] == 'sucesso':
                if not resposta['conteudo']['pastas'] and not resposta['conteudo']['ficheiros']:
                    print("\nO cofre está vazio!")
                else:
                    if resposta['conteudo']['pastas']:
                        print("\nPastas:")
                        for pasta in resposta['conteudo']['pastas']:
                            print(f"Nome: {pasta['nome']}")
                            print(f"ID: {pasta['id']}")
                            print("---")
                    if resposta['conteudo']['ficheiros']:
                        print("\nficheiros:")
                        for ficheiro in resposta['conteudo']['ficheiros']:
                            print(f"ID: {ficheiro['id']}")
                            print(f"Nome: {ficheiro['nome']}")
                            print(f"Tamanho: {ficheiro['tamanho']} bytes")
                            print(f"Data: {ficheiro['data_upload']}")
                            print("---")
            else:
                print(resposta['mensagem'])
        
        elif opcao == '2':
            nome = input("Digite o nome da nova pasta: ")
            resposta = cliente.criar_pasta(nome)
            print(resposta['mensagem'])
        
        elif opcao == '3':
            try:
                nome = input("Digite o nome do ficheiro: ")
                caminho = input("Digite o caminho do ficheiro: ")
                
                # Verificar se o ficheiro existe
                if not os.path.exists(caminho):
                    print("ficheiro não encontrado!")
                    continue
                
                # Verificar tamanho do ficheiro
                tamanho = os.path.getsize(caminho)
                if tamanho > 10 * 1024 * 1024:  # Limite de 10MB por exemplo
                    print("ficheiro muito grande!")
                    continue
                
                resposta = cliente.upload_ficheiro(nome, caminho)
                print(resposta['mensagem'])
            except Exception as e:
                print(f"Erro ao fazer upload: {e}")
        
        elif opcao == '4':
            print("\nGerenciar Permissões:")
            print("1. Conceder permissão")
            print("2. Remover permissão")
            print("3. Alterar nível de permissão")
            print("4. Voltar")
            
            opcao_perm = input("Escolha uma opção: ")
            
            if opcao_perm == '1':
                recurso_id = input("Digite o ID do recurso: ")
                tipo = input("Digite o tipo (ficheiro/pasta): ")
                email = input("Digite o email do utilizador: ")
                print("Níveis de permissão disponíveis:")
                print("1. read")
                print("2. append")
                print("3. write")
                nivel = input("Escolha o nível de permissão (1-3): ")
                niveis = ['read', 'append', 'write']
                if nivel.isdigit() and 1 <= int(nivel) <= 3:
                    resposta = cliente.conceder_permissao(
                        email, recurso_id, tipo, niveis[int(nivel)-1]
                    )
                    print(resposta['mensagem'])
                else:
                    print("Nível inválido")
            
            elif opcao_perm == '2':
                recurso_id = input("Digite o ID do recurso: ")
                tipo = input("Digite o tipo (ficheiro/pasta): ")
                email = input("Digite o email do utilizador: ")
                resposta = cliente.remover_permissao(email, recurso_id, tipo)
                print(resposta['mensagem'])
            
            elif opcao_perm == '3':
                recurso_id = input("Digite o ID do recurso: ")
                tipo = input("Digite o tipo (ficheiro/pasta): ")
                email = input("Digite o email do utilizador: ")
                print("Novos níveis de permissão disponíveis:")
                print("1. read")
                print("2. append")
                print("3. write")
                nivel = input("Escolha o novo nível de permissão (1-3): ")
                niveis = ['read', 'append', 'write']
                if nivel.isdigit() and 1 <= int(nivel) <= 3:
                    resposta = cliente.alterar_permissao(
                        email, recurso_id, tipo, niveis[int(nivel)-1]
                    )
                    print(resposta['mensagem'])
                else:
                    print("Nível inválido")
            
            elif opcao_perm == '4':
                continue
        
        elif opcao == '5':
            pasta_id = input("Digite o ID da pasta que deseja entrar: ")
            # Envia comando para o servidor verificar a pasta
            mensagem = {
                'comando': 'verificar_pasta',
                'pasta_id': pasta_id,
                'user_id': cliente.user_atual['id']
            }
            resposta = cliente.enviar_mensagem(mensagem)
            
            if resposta['status'] == 'sucesso':
                menu_pasta(cliente, pasta_id)
            else:
                print(f"Erro: {resposta['mensagem']}")
        
        elif opcao == '6':
            mensagem = {
                'comando': 'listar_permissoes',
                'user_id': cliente.user_atual['id']
            }
            resposta = cliente.enviar_mensagem(mensagem)
            
            if resposta['status'] == 'sucesso':
                if not resposta['conteudo']['pastas'] and not resposta['conteudo']['ficheiros']:
                    print("\nVocê não tem permissões em nenhum recurso!")
                else:
                    if resposta['conteudo']['pastas']:
                        print("\nPastas com permissão:")
                        for pasta in resposta['conteudo']['pastas']:
                            print(f"Nome: {pasta['nome']}")
                            print(f"ID: {pasta['id']}")
                            print(f"Nível de permissão: {pasta['nivel_permissao']}")
                            print(f"Dono: {pasta['dono']}")
                            print("---")
                    if resposta['conteudo']['ficheiros']:
                        print("\nFicheiros com permissão:")
                        for ficheiro in resposta['conteudo']['ficheiros']:
                            print(f"ID: {ficheiro['id']}")
                            print(f"Nome: {ficheiro['nome']}")
                            print(f"Tamanho: {ficheiro['tamanho']} bytes")
                            print(f"Data: {ficheiro['data_upload']}")
                            print(f"Nível de permissão: {ficheiro['nivel_permissao']}")
                            print(f"Dono: {ficheiro['dono']}")
                            print("---")
            else:
                print(resposta['mensagem'])

        elif opcao == '7':
            ficheiro_id = input("Digite o ID do ficheiro que deseja ler: ")
            resposta = cliente.ler_ficheiro(ficheiro_id)
            print(resposta['mensagem'])

        elif opcao == '8':
            ficheiro_id = input("Digite o ID do ficheiro que deseja editar: ")
            resposta = cliente.modificar_conteudo_ficheiro(ficheiro_id)
            print(resposta['mensagem'])

        elif opcao == '9':
            ficheiro_id = input("Digite o ID do ficheiro que deseja adicionar conteúdo: ")
            resposta = cliente.adicionar_conteudo_ficheiro(ficheiro_id)
            print(resposta['mensagem'])
            
        elif opcao == '10':
            cliente.user_atual = None
            break
            
        elif opcao == '11':
            email = input("Digite seu email: ")
            senha = getpass("Digite sua senha: ")
            resposta = cliente.remover_conta(email, senha)
            print(resposta['mensagem'])
            if resposta['status'] == 'sucesso':
                cliente.user_atual = None
            break

def menu():
    try:
        cliente = Cliente()
        while True:
            if cliente.user_atual is None:
                print("\n1. Criar conta")
                print("2. Login")
                print("3. Sair")
                opcao = input("Escolha uma opção: ")

                if opcao == '1':
                    email = input("Digite seu email: ")
                    senha = input("Digite sua senha: ")
                    resposta = cliente.criar_conta(email, senha)
                    print(resposta['mensagem'])

                elif opcao == '2':
                    email = input("Digite seu email: ")
                    senha = getpass("Digite sua senha: ")
                    resposta = cliente.login(email, senha)
                    if resposta['status'] == 'sucesso':
                        cliente.user_atual = resposta['user']
                        cliente.cofre_id = resposta['user']['cofre_id']
                        print(f"Bem-vindo ao seu cofre digital!")
                        menu_principal(cliente)
                    else:
                        print(resposta['mensagem'])

                elif opcao == '3':
                    break
            else:
                menu_principal(cliente)

    except Exception as e:
        print(f"Erro: {e}")

if __name__ == '__main__':
    menu()
