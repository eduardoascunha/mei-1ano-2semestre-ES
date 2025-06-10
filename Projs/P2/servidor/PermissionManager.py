from servidor.DBManager import DBManager

class PermissionManager:
    def __init__(self):
        pass

    def tem_acesso_pasta(self, email, pasta_id):
        cursor = DBManager()

        user_id = cursor.obter_id_from_email_db(email) 

        # verificar se o user é o dono do cofre
        if cursor.obter_cofreID_db(user_id) == cursor.obter_cofreID_from_pasta_db(pasta_id):
            return True

        # verificar se o user tem permissão na pasta
        return cursor.existe_permissao_pasta_db(user_id, pasta_id)

    def listar_recursos_com_permissao(self, email):
        cursor = DBManager()
        user_id = cursor.obter_id_from_email_db(email)
        return cursor.listar_recursos_com_permissao_db(user_id)

    def dono_do_recurso(self, dono_id, recurso_id, tipo_recurso):
        cursor = DBManager()
        cofre_id = cursor.obter_cofreID_db(dono_id)
        return cursor.dono_do_recurso_db(cofre_id, recurso_id, tipo_recurso)

    def criar_permissao(self, email_autenticado, email_user, recurso_id, tipo_recurso, nivel, chave_ficheiro_cifrada=None):
        cursor = DBManager()
        dono_id = cursor.obter_id_from_email_db(email_autenticado)

        if not self.dono_do_recurso(dono_id, recurso_id, tipo_recurso):
            return {'status': 'erro', 'mensagem': 'User não é dono do ficheiro'}

        user_id = cursor.obter_id_from_email_db(email_user)

        return cursor.criar_permissao_db(user_id, recurso_id, tipo_recurso, nivel, chave_ficheiro_cifrada)

    def remover_permissao(self, email_autenticado, email_user, recurso_id, tipo_recurso):
        cursor = DBManager()
        dono_id = cursor.obter_id_from_email_db(email_autenticado)

        if not self.dono_do_recurso(dono_id, recurso_id, tipo_recurso):
            return {'status': 'erro', 'mensagem': 'User não é dono do ficheiro'}

        user_id = cursor.obter_id_from_email_db(email_user)

        return cursor.remover_permissao_db(user_id, recurso_id, tipo_recurso)

    def alterar_permissao(self, email_autenticado, email_user, recurso_id, tipo_recurso, nivel):
        cursor = DBManager()
        dono_id = cursor.obter_id_from_email_db(email_autenticado)

        if not self.dono_do_recurso(dono_id, recurso_id, tipo_recurso):
            return {'status': 'erro', 'mensagem': 'User não é dono do ficheiro'}

        user_id = cursor.obter_id_from_email_db(email_user)

        return cursor.alterar_permissao_db(user_id, recurso_id, tipo_recurso, nivel)
        


    