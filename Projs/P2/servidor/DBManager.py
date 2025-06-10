
import psycopg2
import os
from dotenv import load_dotenv
from psycopg2 import Error
import base64
from datetime import datetime
import hashlib
import pyotp

class DBManager:
    def __init__(self):
        self.conexao = None
        self.inicializar_base_dados()
        
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
            
        except (Exception, Error) as error:
            print(f"Erro ao conectar ao PostgreSQL: {error}")
            raise

    def existe_email_db(self, email):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE email = %s)", (email,))
        existe = cursor.fetchone()[0]
        cursor.close()
        return existe

    def obter_email_por_id_db(self, user_id):
        try:
            cursor = self.conexao.cursor()
            cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
            resultado = cursor.fetchone()

            if resultado:
                return resultado[0]
            
            else:
                return {
                    'status': 'erro',
                    'mensagem': 'Email não encontrado'
                }   
                
        except Exception as e:
            return {
                'status': 'erro',
                'mensagem': f'{e}'
            }
        
        finally:
            cursor.close()

    def criar_conta_db(self, email, senha_hash, chave_publica_base64):
        try:
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

            return {
                'status': 'sucesso',
                'mensagem': 'Conta e cofre pessoal criados com sucesso',
                'user': {
                    'id': str(user_id),
                    'cofre_id': str(cofre_id)
                }
            }
        
        except Exception as e:
            print(f"Erro ao criar conta: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao criar conta'}
        
        finally:
            cursor.close()
            
    def obter_id_senha_hash_db(self, email):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT id, senha_hash FROM users WHERE email = %s", (email,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado
    
    def obter_id_from_email_db(self, email):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado

    def obter_cofreID_db(self, user_id):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT id FROM cofres WHERE dono_id = %s", (user_id,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado

    def obter_cofreID_from_pasta_db(self, pasta_id):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT cofre_id FROM pastas WHERE id = %s", (pasta_id,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado

    def remover_conta_db(self, user_id):
        cofre_id = self.obter_cofreID_db(user_id)

        if not cofre_id:
            return {'status': 'erro', 'mensagem': 'Cofre do user não encontrado'}

        try:
            cursor = self.conexao.cursor()

            # Remover todas as permissões do user
            cursor.execute("DELETE FROM permissoes WHERE user_id = %s", (user_id,))
            
            # Remover as chaves de ficheiros associadas ao user
            cursor.execute("DELETE FROM chaves WHERE user_id = %s", (user_id,))
            
            # Remover todos os ficheiros do cofre
            cursor.execute("DELETE FROM ficheiros WHERE cofre_id = %s", (cofre_id,))
            
            # Remover todas as pastas do cofre
            cursor.execute("DELETE FROM pastas WHERE cofre_id = %s", (cofre_id,))
            
            # Remover o cofre
            cursor.execute("DELETE FROM cofres WHERE id = %s", (cofre_id,))
            
            # Remover o user
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            
            self.conexao.commit()
            return {'status': 'sucesso', 'mensagem': 'Conta removida com sucesso'}
        
        except Exception as e:
            print(f"Erro ao remover conta: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao remover conta'}
        
        finally:
            cursor.close()

    def listar_pastas_ficheiros_do_cofre_db(self, cofre_id):
        try:
            cursor = self.conexao.cursor()
            
            # listar pastas
            cursor.execute(
                """
                SELECT id, nome, data_criacao
                FROM pastas
                WHERE cofre_id = %s and pasta_pai_id is NULL
                ORDER BY nome
                """,
                (cofre_id,)
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
                WHERE cofre_id = %s
                ORDER BY nome
                """,
                (cofre_id,)
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
        
            return {
                'status': 'sucesso',
                'conteudo': {
                    'pastas': pastas,
                    'ficheiros': ficheiros
                }
            }

        except Exception as e:
            print(f"Erro ao listar conteúdo: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao listar conteudo'}

    def criar_pasta_db(self, nome, cofre_id, pasta_pai_id):
        if self.obter_profundidade_pasta(pasta_pai_id) >= 3:
            return {'status': 'erro', 'mensagem': 'Profundidade maxima de pastas atingida'}
        
        try: 
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
            return {'status': 'erro', 'mensagem': 'Erro ao criar pasta'}

    def obter_profundidade_pasta(self, pasta_pai_id):
        profundidade = 0
        cursor = self.conexao.cursor()
        atual_id = pasta_pai_id
        while atual_id:
            cursor.execute("SELECT pasta_pai_id FROM pastas WHERE id = %s", (atual_id,))
            row = cursor.fetchone()
            if row and row[0]:
                atual_id = row[0]
                profundidade += 1
            else:
                break
        cursor.close()
        return profundidade

    def remover_pasta_db(self, pasta_id):
        try: 
            cursor = self.conexao.cursor()
            cursor.execute(
                "DELETE FROM pastas WHERE id = %s",
                (pasta_id,)
            )
            self.conexao.commit()
            return {'status': 'sucesso', 'mensagem': 'Pasta removida com sucesso'}
        
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao remover pasta: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao remover pasta'}

    def listar_pasta_db(self, pasta_id): 
        try:
            cursor = self.conexao.cursor()
            
            # Listar nomes das subpastas
            cursor.execute(
                """
                SELECT nome
                FROM pastas
                WHERE pasta_pai_id = %s
                ORDER BY nome
                """,
                (pasta_id,)
            )
            subpastas = [row[0] for row in cursor.fetchall()]
            
            # Listar ficheiros na pasta
            cursor.execute(
                """
                SELECT id, nome, tamanho, data_upload
                FROM ficheiros
                WHERE pasta_id = %s
                ORDER BY nome
                """,
                (pasta_id,)
            )
            ficheiros = [
                {
                    'id': str(row[0]),
                    'nome': row[1],
                    'tipo': 'ficheiro',
                    'tamanho': row[2],
                    'data_upload': row[3].isoformat() if row[3] else None
                }
                for row in cursor.fetchall()
            ]
            
            return {
                'status': 'sucesso',
                'conteudo': {
                    'subpastas': subpastas,   # Só nomes das subpastas
                    'ficheiros': ficheiros
                }
            }
        except Exception as e:
            print(f"Erro ao listar conteúdo da pasta: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao listar conteúdo da pasta'}

    def obter_id_pasta_por_nome_e_parent(self, pasta_nome, pasta_pai_id, cofre_id):
        try:
            cursor = self.conexao.cursor()
            if pasta_pai_id is None:
                cursor.execute(
                    """
                    SELECT id FROM pastas
                    WHERE nome = %s AND pasta_pai_id IS NULL AND cofre_id = %s
                    """,
                    (pasta_nome, cofre_id)
                )
            else:
                cursor.execute(
                    """
                    SELECT id FROM pastas
                    WHERE nome = %s AND pasta_pai_id = %s AND cofre_id = %s
                    """,
                    (pasta_nome, pasta_pai_id, cofre_id)
                )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            print(f"Erro ao obter id da pasta: {e}")
            return None

    #########
    # perms #
    #########
    def existe_permissao_pasta_db(self, user_id, pasta_id):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT 1 FROM permissoes
                WHERE user_id = %s
                AND recurso_id = %s
                AND tipo_recurso = 'pasta'
                LIMIT 1
                """,
                (user_id, pasta_id)
            )
            return cursor.fetchone() is not None
        except Exception as e:
            print(f"Erro ao verificar permissão: {e}")
            return False

    
    def listar_recursos_com_permissao_db(self, user_id):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT 
                    p.recurso_id AS id,
                    pa.nome AS nome,
                    'pasta' AS tipo,
                    p.nivel AS nivel,
                    u.email AS dono_email
                FROM permissoes p
                JOIN pastas pa ON p.recurso_id = pa.id
                JOIN cofres c ON pa.cofre_id = c.id
                JOIN users u ON c.dono_id = u.id
                WHERE p.user_id = %s AND p.tipo_recurso = 'pasta'
                
                UNION ALL
                
                SELECT 
                    p.recurso_id AS id,
                    f.nome AS nome,
                    'ficheiro' AS tipo,
                    p.nivel AS nivel,
                    u.email AS dono_email
                FROM permissoes p
                JOIN ficheiros f ON p.recurso_id = f.id
                JOIN cofres c ON f.cofre_id = c.id
                JOIN users u ON c.dono_id = u.id
                WHERE p.user_id = %s AND p.tipo_recurso = 'ficheiro'
                """,
                (user_id, user_id)
            )
            
            recursos = [
                {
                    'id': str(row[0]),
                    'nome': row[1],
                    'tipo': row[2],
                    'nivel': row[3],
                    'dono_email': row[4]
                }
                for row in cursor.fetchall()
            ]
            cursor.close()
            return {'status': 'sucesso', 'recursos': recursos}
            
        except Exception as e:
            print(f"Erro ao listar recursos com permissão: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao listar recursos com permissão'}

    def verificar_permissao_user_ficheiro(self, user_id, ficheiro_id, nivel):
        cursor = self.conexao.cursor()
        cursor.execute(
            """
            SELECT nivel FROM permissoes WHERE user_id = %s AND recurso_id = %s 
            """,
            (user_id, ficheiro_id)
        )
        resultado = cursor.fetchone()[0]
        niveis_permitidos = ['read', 'append', 'write']
        if resultado in niveis_permitidos:
            if niveis_permitidos.index(resultado) >= nivel:
                return True
            else:
                return False
        cursor.close()
        return resultado

    def dono_do_recurso_db(self, cofre_id, recurso_id, tipo_recurso):
        cursor = self.conexao.cursor()
        tabelas_validas = {"ficheiro", "pasta"}  
        if tipo_recurso not in tabelas_validas:
            raise ValueError("Tipo de recurso invalido")

        if tipo_recurso == "ficheiro":
            tipo_recurso = "ficheiros"
        elif tipo_recurso == "pasta":
            tipo_recurso = "pastas"

        query = f"""
            SELECT 1 FROM {tipo_recurso}
            WHERE cofre_id = %s
            AND id = %s
            LIMIT 1
        """
        cursor.execute(query, (cofre_id, recurso_id))
        return cursor.fetchone() is not None

    def criar_permissao_db(self, user_id, recurso_id, tipo_recurso, nivel, chave_ficheiro_cifrada=None):
        data_concessao = datetime.now()
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                INSERT INTO permissoes (user_id, recurso_id, tipo_recurso, nivel, data_concessao)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, recurso_id, tipo_recurso, nivel, data_concessao)
            )

            if chave_ficheiro_cifrada:
                # Armazenar a chave cifrada na tabela "chaves"
                cursor.execute(
                    """
                    INSERT INTO chaves (ficheiro_id, user_id, chave_cifrada)
                    VALUES (%s, %s, %s)
                    """,
                    (recurso_id, user_id, chave_ficheiro_cifrada)
                )
            self.conexao.commit()
            cursor.close()
            return {'status': 'sucesso', 'mensagem': 'Permissão criada'}
        except psycopg2.IntegrityError:
            self.conexao.rollback()
            return {'status': 'erro', 'mensagem': 'Permissão ja existe para este utilizador e recurso'}
        except Exception as e:
            self.conexao.rollback()
            return {'status': 'erro', 'mensagem': f'Erro ao criar permissão: {str(e)}'}

    def remover_permissao_db(self, user_id, recurso_id, tipo_recurso):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                DELETE FROM permissoes
                WHERE user_id = %s
                AND recurso_id = %s
                AND tipo_recurso = %s
                """,
                (user_id, recurso_id, tipo_recurso)
            )
            if tipo_recurso == "ficheiro":
                cursor.execute(
                    """
                    DELETE FROM chaves
                    WHERE user_id = %s
                    AND ficheiro_id = %s
                    """,
                    (user_id, recurso_id)
                )
            self.conexao.commit()
            cursor.close()
            return {'status': 'sucesso', 'mensagem': 'Permissão removida'}
        except Exception as e:
            self.conexao.rollback()
            return {'status': 'erro', 'mensagem': f'Erro ao remover permissão: {str(e)}'}

    def alterar_permissao_db(self, user_id, recurso_id, tipo_recurso, nivel):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                UPDATE permissoes
                SET nivel = %s
                WHERE user_id = %s
                AND recurso_id = %s
                AND tipo_recurso = %s
                """,
                (nivel, user_id, recurso_id, tipo_recurso)
            )
            self.conexao.commit()
            cursor.close()
            return {'status': 'sucesso', 'mensagem': 'Permissão alterada'}
        except Exception as e:
            self.conexao.rollback()
            return {'status': 'erro', 'mensagem': f'Erro ao alterar permissão: {str(e)}'}

    #########
    # files #
    #########

    def upload_ficheiro_db(self, nome, conteudo_cifrado_base64, iv_base64, tag_base64, chave_cifrada_base64, pasta_id, user_id, cofre_id):
        try:
            # Descodificar o conteúdo de base64 (só para verificar se é valido)
            try:
                conteudo = base64.b64decode(conteudo_cifrado_base64)
            except:
                return {'status': 'erro', 'mensagem': 'Conteúdo do ficheiro invalido'}
            
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                INSERT INTO ficheiros (nome, cofre_id, pasta_id, conteudo, iv, tag, tipo, tamanho)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, data_upload
                """,
                (nome, cofre_id, pasta_id, conteudo_cifrado_base64, iv_base64, tag_base64, 'ficheiro', len(conteudo_cifrado_base64))
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

            cursor.execute(
                """
                INSERT INTO permissoes (user_id, recurso_id, tipo_recurso, nivel)
                VALUES (%s, %s, 'ficheiro', 'write')
                """,
                (user_id, ficheiro_id)
            )

            self.armazenar_hash_ficheiro(ficheiro_id, conteudo_cifrado_base64)

            self.conexao.commit()

            return {
                'status': 'sucesso',
                'mensagem': 'Ficheiro carregado com sucesso',
                'ficheiro': {
                    'id': str(ficheiro_id),
                    'nome': nome
                }
            }
        
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao carregar ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao carregar ficheiro'}
        
    def remover_ficheiro_db(self, ficheiro_id):
        try: 
            cursor = self.conexao.cursor()

            cursor.execute(
                "DELETE FROM ficheiros WHERE id = %s",
                (ficheiro_id,)
            )

            # Remover as chaves cifradas associadas ao ficheiro
            cursor.execute(
                "DELETE FROM chaves WHERE ficheiro_id = %s",
                (ficheiro_id,)
            )

            self.conexao.commit()
            return {'status': 'sucesso', 'mensagem': 'Ficheiro removido com sucesso'}
        
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao remover ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao remover ficheiro'}
        
    def ler_ficheiro_db(self, ficheiro_id, user_id):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT conteudo, iv, tag
                FROM ficheiros
                WHERE id = %s
                """,
                (ficheiro_id,)
            )
            resultado_ficheiro = cursor.fetchone()

            if not resultado_ficheiro:
                return {'status': 'erro', 'mensagem': 'Ficheiro não encontrado'}

            conteudo_cifrado, iv, tag = resultado_ficheiro

            cursor.execute(
                """
                SELECT chave_cifrada
                FROM chaves
                WHERE ficheiro_id = %s AND user_id = %s
                """,
                (ficheiro_id, user_id)
            )
            resultado_chave = cursor.fetchone()

            if not resultado_chave:
                return {'status': 'erro', 'mensagem': 'Chave do ficheiro não encontrada'}
            
            chave_cifrada = resultado_chave[0]

            return {
                'status': 'sucesso',
                'conteudo': conteudo_cifrado,
                'iv': iv,
                'tag': tag,
                'chave_cifrada': chave_cifrada
            }
        
        except Exception as e:
            print(f"Erro ao ler ficheiro 2: {e} ")
            return {'status': 'erro', 'mensagem': 'Erro ao ler ficheiro'}
        
    def modificar_ficheiro_db(self, ficheiro_id, conteudo_cifrado_base64, iv_base64, tag_base64):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                UPDATE ficheiros
                SET conteudo = %s, iv = %s, tag = %s
                WHERE id = %s
                """,
                (conteudo_cifrado_base64, iv_base64, tag_base64, ficheiro_id)
            )

            self.armazenar_hash_ficheiro(ficheiro_id, conteudo_cifrado_base64)
            
            self.conexao.commit()
            
            return {
                'status': 'sucesso',
                'mensagem': 'Ficheiro modificado com sucesso'
            }
        
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao modificar ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao modificar ficheiro'}
        
    def adicionar_ao_ficheiro_db(self, ficheiro_id, conteudo_cifrado_base64, iv_base64, tag_base64):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                UPDATE ficheiros
                SET conteudo = %s, iv = %s, tag = %s
                WHERE id = %s
                """,
                (conteudo_cifrado_base64, iv_base64, tag_base64, ficheiro_id)
            )

            self.armazenar_hash_ficheiro(ficheiro_id, conteudo_cifrado_base64)

            self.conexao.commit()
            
            return {
                'status': 'sucesso',
                'mensagem': 'Conteúdo adicionado ao ficheiro com sucesso'
            }
        
        except Exception as e:
            self.conexao.rollback()
            print(f"Erro ao adicionar conteúdo ao ficheiro: {e}")
            return {'status': 'erro', 'mensagem': 'Erro ao adicionar conteúdo ao ficheiro'}
    
    def obter_chave_publica_db(self, email_user):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT chave_publica
                FROM users
                WHERE email = %s
                """,
                (email_user,)
            )
            resultado = cursor.fetchone()

            if resultado:
                return {
                    'status': 'sucesso',
                    'chave_publica': resultado[0]
                }
            
            else:
                return {
                    'status': 'erro',
                    'mensagem': 'Chave pública não encontrada'
                }   
                
        except Exception as e:
            return {
                'status': 'erro',
                'mensagem': f'{e}'
            }
        
        finally:
            cursor.close()
     
    def obter_chave_ficheiro_db(self, user_id, ficheiro_id):
        try:
            cursor = self.conexao.cursor()
            cursor.execute(
                """
                SELECT chave_cifrada FROM chaves
                WHERE user_id = %s AND ficheiro_id = %s
                """,
                (user_id, ficheiro_id)
            )
            resultado = cursor.fetchone()
            
            if resultado is None:
                return {
                    'status': 'erro',
                    'mensagem': 'Chave não encontrada'
                }
            
            chave_ficheiro = resultado[0]
            return {
                'status': 'sucesso',
                'conteudo': chave_ficheiro
            }
        except Exception as e:
            print(f"Erro ao obter chave do ficheiro: {e}")
            return {
                'status': 'erro',
                'mensagem': f'Erro ao obter chave: {str(e)}'
            }
        finally:
            cursor.close()

    def obter_id_ficheiro_por_nome_e_parent(self, ficheiro_nome, pasta_id, cofre_id):
        try:
            cursor = self.conexao.cursor()
            if pasta_id is None:
                cursor.execute(
                    """
                    SELECT id FROM ficheiros
                    WHERE nome = %s AND pasta_id IS NULL AND cofre_id = %s
                    """,
                    (ficheiro_nome, cofre_id)
                )
            else:
                cursor.execute(
                    """
                    SELECT id FROM ficheiros
                    WHERE nome = %s AND pasta_id = %s AND cofre_id = %s
                    """,
                    (ficheiro_nome, pasta_id, cofre_id)
                )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            print(f"Erro ao obter id do ficheiro: {e}")
            return None
        finally:
            cursor.close()

    ##############
    ## Integridade (falta adicionar o campo na tabela ficheiros)
    ##############

    def armazenar_hash_ficheiro(self, ficheiro_id, conteudo_cifrado):
        hash_valor = hashlib.sha256(conteudo_cifrado.encode('utf-8') if isinstance(conteudo_cifrado, str) else conteudo_cifrado).hexdigest()
        
        # Usar um cursor do objeto conexao
        cursor = self.conexao.cursor()
        
        # Armazenar o hash na tabela de ficheiros
        query = "UPDATE ficheiros SET hash_verificacao = %s WHERE id = %s"
        cursor.execute(query, (hash_valor, ficheiro_id))
        
        # Não é necessário fazer commit aqui, será feito no método principal
        # self.conexao.commit()
        
        return hash_valor

    def obter_todos_ficheiros_ids_bd(self):
        cursor = self.conexao.cursor()
        
        query = "SELECT id FROM ficheiros"
        cursor.execute(query)
        
        # Obter os resultados e extrair apenas os IDs
        ids = [row[0] for row in cursor.fetchall()]
        
        return ids

    def verificar_integridade_ficheiro(db, ficheiro_id):
        cursor = db.conexao.cursor()

        query = "SELECT hash_verificacao, conteudo FROM ficheiros WHERE id = %s"
        cursor.execute(query, (ficheiro_id,))
        resultado = cursor.fetchone()
        
        if not resultado:
            return False
        
        hash_armazenado, conteudo_cifrado = resultado
        
        # Calcular o hash do conteúdo cifrado atual
        import hashlib
        hash_calculado = hashlib.sha256(conteudo_cifrado.encode('utf-8') if isinstance(conteudo_cifrado, str) else conteudo_cifrado).hexdigest()
        
        # Comparar os hashes
        return hash_armazenado == hash_calculado

    #######
    # 2fa #
    #######

    def two_fa_ativado(self, email):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT two_fa_ativado FROM users WHERE email = %s", (email,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado[0] if resultado else False

    def ativar_2fa_db(self, user_id, email):
        secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="NomeDaTuaApp")

        cursor = self.conexao.cursor()
        cursor.execute(
            "UPDATE users SET two_fa_ativado = TRUE, two_fa_secret = %s WHERE id = %s",
            (secret, user_id)
        )
        self.conexao.commit()
        return secret, uri

    def desativar_2fa_db(self, user_id):
        cursor = self.conexao.cursor()
        cursor.execute("UPDATE users SET two_fa_ativado = False WHERE id = %s", (user_id,))
        self.conexao.commit()
        return True
    
    def get_two_fa_secret_by_email(self, email):
        cursor = self.conexao.cursor()
        cursor.execute("SELECT two_fa_secret FROM users WHERE email = %s", (email,))
        resultado = cursor.fetchone()
        cursor.close()
        return resultado[0] if resultado else None
        