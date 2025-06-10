import typer
from cliente import Cliente
cliente = Cliente()

app = typer.Typer()

@app.command(name="criar-conta")
def criar_conta(email: str, password: str):
    """Cria uma nova conta de utilizador."""
    cliente.criar_conta(email, password)

@app.command(name="login")
def login(email: str, password: str):
    """Faz login na conta."""
    cliente.login(email, password)

@app.command(name="ativar-2fa")
def ativar_2fa():
    """Ativa o 2FA na conta."""
    cliente.ativar_2fa()

@app.command(name="desativar-2fa")
def desativar_2fa():
    """Desativa o 2FA na conta."""
    cliente.desativar_2fa()

@app.command(name="login-google")
def login_google():
    """Faz login na conta com Google."""
    cliente.login_google()

@app.command(name="remover-conta")
def remover_conta(email: str, password: str):
    """Remove a conta de utilizador."""
    cliente.remover_conta(email, password)

@app.command(name="logout")
def logout():
    """Faz logout na conta."""
    cliente.logout()

@app.command(name="listar-conteudo-cofre")
def listar_conteudo():
    """Lista o conteudo do cofre pessoal."""
    cliente.listar_conteudo_cofre()

@app.command(name="criar-pasta-na-raiz")
def criar_pasta(nome: str, pasta_pai_id: str=None): # envia pasta_pai_id sempre igual a null pra criar na root
    """Cria uma nova pasta."""
    cliente.criar_pasta(nome, pasta_pai_id)

@app.command(name="criar-pasta")
def criar_pasta(nome: str, pasta_pai_id: str): # precisa de indicar o id da pasta pai
    """Cria uma nova pasta."""
    cliente.criar_pasta(nome, pasta_pai_id)

@app.command(name="remover-pasta")
def remover_pasta(pasta_id: str):
    """Remove uma pasta."""
    cliente.remover_pasta(pasta_id)

@app.command(name="listar-conteudo-pasta")
def listar_conteudo_pasta(pasta_id: str):
    """Lista o conteudo de uma pasta."""
    cliente.listar_conteudo_pasta(pasta_id)

@app.command(name="listar-permissoes")
def listar_recursos_com_permissao():
    """Lista os recursos com permissão."""
    cliente.listar_recursos_com_permissao()

@app.command(name="conceder-permissao")
def conceder_permissao(email_user: str, recurso_id: str, tipo_recurso: str, nivel: str):
    """Concede permissão a um recurso."""
    cliente.conceder_permissao(email_user, recurso_id, tipo_recurso, nivel)

@app.command(name="remover-permissao")
def remover_permissao(email_user: str, recurso_id: str, tipo_recurso: str):
    """Remove permissão de um recurso."""
    cliente.remover_permissao(email_user, recurso_id, tipo_recurso)

@app.command(name="alterar-permissao")
def alterar_permissao(email_user: str, recurso_id: str, tipo_recurso: str, nivel: str):
    """Altera permissão de um recurso."""
    cliente.alterar_permissao(email_user, recurso_id, tipo_recurso, nivel)

@app.command(name="upload-ficheiro")
def upload_ficheiro(email: str, path_ficheiro: str, pasta_pai_id: str = None):
    """Faz upload de um ficheiro."""
    cliente.upload_ficheiro(email,path_ficheiro, pasta_pai_id=pasta_pai_id)

@app.command(name="remover-ficheiro")
def remover_ficheiro(path_ficheiro: str):
    """Remove um ficheiro."""
    cliente.remover_ficheiro(path_ficheiro)

@app.command(name="ler-ficheiro")
def ler_ficheiro(email: str, ficheiro_id: str):
    """Lê o conteudo de um ficheiro."""
    cliente.ler_ficheiro(email,ficheiro_id)

@app.command(name="modificar-ficheiro")
def modificar_ficheiro(email: str,ficheiro_id: str):
    """Modifica um ficheiro."""
    cliente.modificar_ficheiro(email,ficheiro_id)

@app.command(name="adicionar-ao-ficheiro")
def adicionar_ao_ficheiro(email: str,ficheiro_id: str):
    """Adiciona conteudo a um ficheiro."""
    cliente.adicionar_ao_ficheiro(email,ficheiro_id)

@app.command(name="logs")
def logs():
    """Lista os logs."""
    cliente.logs()

# so para testes
@app.command(name="refresh")
def refresh():
    """Renova o token."""
    cliente.refresh()

if __name__ == "__main__":
    app()
