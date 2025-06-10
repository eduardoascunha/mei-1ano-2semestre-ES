from fastapi import FastAPI, HTTPException, Depends, Request, Body, status, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, validator
from dotenv import load_dotenv
import os
import json
import ssl
import uvicorn
import re
from datetime import timedelta
from servidor.auth import add_blacklist, criar_token_dados, criar_refresh_token, verificar_access_token, verificar_refresh_token, oauth2_scheme
from uuid import UUID
import base64
import requests
import pyotp
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from servidor.AccountManager import AccountManager
AccountManager = AccountManager()

from servidor.DBManager import DBManager
DBManager = DBManager()

from servidor.PermissionManager import PermissionManager
PermissionManager = PermissionManager()

from servidor.IntegrityManager import verificar_integridade_todos_ficheiros

from servidor.Logger import Logger
load_dotenv()
Logger = Logger(
    password=os.getenv('LOG_PASSWORD'),
    log_path=os.getenv('LOG_PATH')
)

# api
app = FastAPI()

# rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

# schema
class Request_Schema(BaseModel):
    email: str | None = None
    password: str | None = None
    code: str | None = None
    chave_publica: str | None = None
    conteudo_cifrado: str | None = None
    iv: str | None = None
    tag: str | None = None
    chave_cifrada: str | None = None
    pasta_id: str | None = None
    pasta_pai_id: str | None = None
    nome: str | None = None
    nome_ficheiro: str | None = None
    user_id: str | None = None
    outro_user_email: str | None = None
    tipo_recurso: str | None = None
    recurso_id: str | None = None
    nivel_acesso: str | None = None
    chave_ficheiro_cifrada: str | None = None

    @validator('email', 'outro_user_email')
    def email_regex(cls, v):
        if v is None:
            return v
        pattern = re.compile(r'^[a-zA-Z0-9._]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if not pattern.match(v):
            raise ValueError('Email inválido')
        return v

    @validator('password')
    def password_regex(cls, v):
        if v is None:
            return v
        pattern = re.compile(r'^[A-Za-z0-9!@#$%^&*_.\-]{5,32}$')
        if not pattern.match(v):
            raise ValueError('Password inválida: só pode conter letras, números e !@#$%^&*_.- (min 5 e max 32 caracteres)')
        return v

    @validator('pasta_id', 'pasta_pai_id', 'user_id', 'recurso_id')
    def uuid_valido(cls, v):
        if v is None:
            return v
        try:
            UUID(v)
        except ValueError:
            raise ValueError('ID inválido (não é UUID)')
        return v

    @validator('chave_publica', 'conteudo_cifrado', 'iv', 'tag', 'chave_cifrada', 'chave_ficheiro_cifrada')
    def base64_valido(cls, v):
        if v is None:
            return v
        try:
            # só aceita base64
            base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError('Campo deve estar em base64')
        return v

    @validator('nome')
    def nome_valido(cls, v):
        if v is None:
            return v
        pattern = re.compile(r'^[A-Za-z\-]{5,32}$')
        if not pattern.match(v):
            raise ValueError('Nome inválido')
        return v

    @validator('tipo_recurso')
    def recurso_valido(cls, v):
        if v is None:
            return v
        if not re.match(r"^(pasta|ficheiro)$", v):
            raise ValueError('Tipo de recurso inválido')
        return v

    @validator('nivel_acesso')
    def novo_nivel_valido(cls, v):
        if v is None:
            return v
        if not re.match(r"^(read|append|write)$", v):
            raise ValueError('Tipo de acesso inválido')
        return v
    
    @validator('nome_ficheiro')
    def nome_ficheiro_valido(cls, v):
        if v is None:
            return v
        pattern = re.compile(r"^[A-Za-z0-9\-_]{5,32}\.txt$")
        if not pattern.match(v):
            raise ValueError('Nome do ficheiro inválido: apenas ficheiros .txt são permitidos')
        return v

    @validator('code')
    def code_valido(cls, v):
        if v is None:
            return v
        pattern = re.compile(r"^[0-9]{6}$")
        if not pattern.match(v):
            raise ValueError('Código 2FA inválido: deve ter 6 dígitos')
        return v


######################
# Para a integridade #
######################

@app.on_event("startup")
def iniciar_verificacao_integridade():
    verificar_integridade_todos_ficheiros()

#############
# endpoints #
#############
@app.post("/criar_conta")
async def criar_conta_endpoint(dados: Request_Schema, request: Request):
    if not dados.email or not dados.password or not dados.chave_publica:
        raise HTTPException(status_code=400, detail="Dados incompletos")
    elif AccountManager.email_existe(dados.email):
        raise HTTPException(status_code=400, detail="Email já registado")
    else:
        ip = request.client.host
        resposta = AccountManager.criar_conta(dados.email, dados.password, dados.chave_publica)
        Logger.registar_log("criar_conta", "sucesso", ip=ip, email=dados.email, detalhes="Sem detalhes")
        return resposta

@app.post("/login")
@limiter.limit("6/minute")
async def login_endpoint(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username
    password = form_data.password
    ip = request.client.host

    if not email or not password or not ip:
        raise HTTPException(status_code=400, detail="Dados incompletos")

    ret = AccountManager.verificar_user(email, password, ip)
    if ret['status'] == 'erro':
        Logger.registar_log("login", "Erro", ip=ip, email=email, detalhes="Email ou password errados")
        raise HTTPException(status_code=400, detail=ret['mensagem'])
    
    if DBManager.two_fa_ativado(email):
        # nao gerar tokens, pedir o codigo 2FA
        return {
            "2fa_required": True,
            "message": "2FA necessário"
        }

    Logger.registar_log("login", "sucesso", ip=ip, email=email, detalhes="Sem detalhes")
    user_id = DBManager.obter_id_from_email_db(email)
    access_token = criar_token_dados(data={"sub": email, "user_id": user_id}) # expiracao do token definida no auth
    refresh_token = criar_refresh_token(data={"sub": email, "user_id": user_id})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@app.post("/login/2fa")
async def login_2fa_endpoint(request: Request, dados: Request_Schema):

    if not dados.email or not dados.code:
        raise HTTPException(status_code=400, detail="Dados incompletos")

    email = dados.email
    code = dados.code
    ip = request.client.host

    if not DBManager.two_fa_ativado(email):
        raise HTTPException(status_code=400, detail="2FA não ativo para este utilizador")

    secret = DBManager.get_two_fa_secret_by_email(email)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        AccountManager.registar_tentativa_login(email, ip)
        Logger.registar_log("login com 2fa", "Erro", ip=ip, email=email, detalhes="Código 2FA inválido")
        raise HTTPException(status_code=400, detail="Código 2FA inválido")

    Logger.registar_log("login com 2fa", "sucesso", ip=ip, email=email, detalhes="Sem detalhes")
    user_id = DBManager.obter_id_from_email_db(email)
    access_token = criar_token_dados(data={"sub": email, "user_id": user_id})
    refresh_token = criar_refresh_token(data={"sub": email, "user_id": user_id})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
    
@app.post("/2fa")
async def ativar_2fa_endpoint(request: Request, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")
    user_id = DBManager.obter_id_from_email_db(email_autenticado)
    secret, uri = DBManager.ativar_2fa_db(user_id, email_autenticado)
    Logger.registar_log("ativar 2fa", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return {"status": "sucesso", "secret": secret, "uri": uri}
    
@app.delete("/2fa")
async def desativar_2fa_endpoint(request: Request, token_data: dict = Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")
    user_id = DBManager.obter_id_from_email_db(email_autenticado)
    if not DBManager.desativar_2fa_db(user_id):
        raise HTTPException(status_code=400, detail="Erro ao desativar 2FA")
    Logger.registar_log("desativar 2fa", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return {"status": "sucesso"}

@app.post("/logout")
async def logout_endpoint(request: Request, token: str = Depends(oauth2_scheme), token_data: dict = Depends(verificar_access_token), 
                          refresh_token: str = Body(..., embed=True)):

    # a verificacao nao pode ser nos parametros para armazenar o token cru
    verificar_refresh_token(refresh_token)

    ip = request.client.host
    email_autenticado = token_data.get("sub")

    add_blacklist(token, "access") # from oauth
    add_blacklist(refresh_token, "refresh")

    Logger.registar_log("logout", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return {"status": "sucesso"}

@app.post("/remover_conta")
async def remover_conta_endpoint(request: Request, dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    if not dados.email or not dados.password:
        raise HTTPException(status_code=400, detail="Dados incompletos")

    ip = request.client.host
    email_autenticado = token_data.get("sub")
    if email_autenticado != dados.email:
        Logger.registar_log("remover_conta", "ERRO", ip=ip, email=email_autenticado, detalhes=f"Emails não correspondem {email_autenticado} tentou remover {dados.email}")
        raise HTTPException(status_code=400, detail="Emails não correspondem")
    
    resposta = AccountManager.remover_conta(email_autenticado, dados.password)
    Logger.registar_log("remover_conta", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return resposta

@app.get("/cofre")
async def cofre_endpoint(request: Request, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    email_autenticado = token_data.get("sub")
    resposta = AccountManager.listar_conteudo_cofre(email_autenticado) #pasta id aqui sempre null 
    Logger.registar_log("listar conteudo cofre", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return resposta

@app.post("/pastas") 
async def criar_pasta_endpoint(request: Request, dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    if not dados.nome:
        raise HTTPException(status_code=400, detail="Dados incompletos")

    email_autenticado = token_data.get("sub")
    resposta = AccountManager.criar_pasta(email_autenticado, dados.pasta_pai_id, dados.nome)
    Logger.registar_log("criar_pasta", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return resposta

@app.delete("/pastas/{pasta_id}")
async def remover_pasta_endpoint(request: Request, pasta_id: str, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")
    
    resposta = AccountManager.remover_pasta(email_autenticado, pasta_id)
    Logger.registar_log("remover_pasta", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return resposta

@app.get("/pastas/{pasta_id}")
async def pasta_endpoint(request: Request, pasta_id: str, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")

    if not PermissionManager.tem_acesso_pasta(email_autenticado, pasta_id):
        Logger.registar_log(f"tentativa de acesso a {pasta_id}", "falha", ip=ip, email=email_autenticado, detalhes=f"Acesso negado a {pasta_id}")
        raise HTTPException(status_code=403, detail="Acesso não autorizado a esta pasta.")

    resposta = AccountManager.listar_conteudo_pasta(pasta_id)
    Logger.registar_log(f"acesso a {pasta_id}", "sucesso", ip=ip, email=email_autenticado, detalhes=f"Acesso a {pasta_id}")
    return resposta

@app.get("/permissoes")
async def recursos_permissoes_endpoint(request: Request, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")

    resposta = PermissionManager.listar_recursos_com_permissao(email_autenticado)
    Logger.registar_log("listar recursos com permissao", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return resposta

@app.post("/permissoes")
async def criar_permissao_endpoint(request: Request, dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")

    # Validar os dados recebidos
    if not dados.outro_user_email or not dados.recurso_id or not dados.tipo_recurso or not dados.nivel_acesso:
        raise HTTPException(status_code=400, detail="Dados incompletos")
    
    if dados.tipo_recurso == "ficheiro":
        if not dados.chave_ficheiro_cifrada:
            raise HTTPException(status_code=400, detail="Dados incompletos")
        else:
            resposta = PermissionManager.criar_permissao(email_autenticado, dados.outro_user_email,dados.recurso_id, dados.tipo_recurso, dados.nivel_acesso, dados.chave_ficheiro_cifrada)
    else:
        resposta = PermissionManager.criar_permissao(email_autenticado, dados.outro_user_email,dados.recurso_id, dados.tipo_recurso, dados.nivel_acesso)
    Logger.registar_log("criar permissao", "sucesso", ip=ip, email=email_autenticado, 
        detalhes=f"Permissão criada para {dados.recurso_id} para o user {dados.outro_user_email} com nivel {dados.nivel_acesso}")
    return resposta

@app.put("/permissoes")
async def alterar_permissao_endpoint(request: Request, dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")

    # Validar os dados recebidos
    if not dados.outro_user_email or not dados.recurso_id or not dados.tipo_recurso or not dados.nivel_acesso:
        raise HTTPException(status_code=400, detail="Dados incompletos")
    
    resposta = PermissionManager.alterar_permissao(email_autenticado, dados.outro_user_email,dados.recurso_id, dados.tipo_recurso, dados.nivel_acesso)
    Logger.registar_log("alterar permissao", "sucesso", ip=ip, email=email_autenticado, 
        detalhes=f"Permissão alterada para {dados.recurso_id} para o user {dados.outro_user_email} para nivel {dados.nivel_acesso}")
    return resposta

@app.delete("/permissoes")
async def remover_permissao_endpoint(request: Request, dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")

    # Validar os dados recebidos
    if not dados.outro_user_email or not dados.recurso_id or not dados.tipo_recurso:
        raise HTTPException(status_code=400, detail="Dados incompletos")
    
    resposta = PermissionManager.remover_permissao(email_autenticado, dados.outro_user_email,dados.recurso_id, dados.tipo_recurso)
    Logger.registar_log("remover permissao", "sucesso", ip=ip, email=email_autenticado, 
        detalhes=f"Permissão removida para {dados.recurso_id} para o user {dados.outro_user_email}")
    return resposta

@app.get("/logs")
async def logs_endpoint(request: Request, token_data: dict = Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")

    ADMIN_EMAILS = json.loads(os.getenv("ADMIN_EMAILS", "[]"))

    if email_autenticado not in ADMIN_EMAILS:
        Logger.registar_log("acesso a logs", "falha", ip=ip, email=email_autenticado, detalhes="Acesso restrito a administradores.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso restrito a administradores."
        )

    resposta = Logger.ler_logs()
    Logger.registar_log("acesso a logs", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return resposta

@app.post("/refresh")
async def refresh_token(request: Request, refresh_token: dict = Depends(verificar_refresh_token)):
    ip = request.client.host
    email_autenticado = refresh_token.get("sub")
    user_id = refresh_token.get("user_id")
    if email_autenticado is None or user_id is None:
        raise HTTPException(status_code=403, detail="Token inválido")

    # gera novo access token
    new_access_token = criar_token_dados(data={"sub": email_autenticado, "user_id": user_id})
    Logger.registar_log("refresh token", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    return {"access_token": new_access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get("/obter_chave_ficheiro/{ficheiro_id}")
async def obter_chave_ficheiro(request: Request, ficheiro_id:str, token_data:dict=Depends(verificar_access_token)):
    
    email_autenticado = token_data.get("sub")

    user_id = DBManager.obter_id_from_email_db(email_autenticado)

    resposta = DBManager.obter_chave_ficheiro_db(user_id, ficheiro_id)
    resposta['email_autenticado'] = email_autenticado
    return resposta

@app.get("/obter_chave_publica/{email_user}")
async def obter_chave_publica(request: Request,email_user:str, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    email_autenticado = token_data.get("sub")
    resposta = DBManager.obter_chave_publica_db(email_user)
    return resposta

@app.post("/ficheiros/upload")
async def upload_ficheiro(request: Request,dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host
    
    # Validar os dados recebidos
    if not dados.nome_ficheiro or not dados.conteudo_cifrado or not dados.iv or not dados.tag or not dados.chave_cifrada:
        return {"status": "erro", "mensagem": "Dados incompletos para upload do ficheiro"}

    email_autenticado = token_data.get("sub")
    resposta = AccountManager.upload_ficheiro(email_autenticado,dados.nome_ficheiro,dados.conteudo_cifrado,dados.iv,dados.tag,dados.chave_cifrada,dados.pasta_pai_id)

    if resposta['status'] == 'sucesso':
        Logger.registar_log("upload_ficheiro", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    else:
        Logger.registar_log("upload_ficheiro", "erro", ip=ip, email=email_autenticado, detalhes=resposta['mensagem'])
    return resposta

@app.delete("/ficheiros/{path_ficheiro}/remover")
async def remover_ficheiro(request: Request,path_ficheiro: str, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    email_autenticado = token_data.get("sub")
    resposta = AccountManager.remover_ficheiro(email_autenticado, path_ficheiro)

    if resposta['status'] == 'sucesso':
        Logger.registar_log("remover_ficheiro", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    else:
        Logger.registar_log("remover_ficheiro", "erro", ip=ip, email=email_autenticado, detalhes=resposta['mensagem'])
    return resposta
    
@app.get("/ficheiros/{ficheiro_id}/ler")
async def ler_ficheiro(request: Request,ficheiro_id: str, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    email_autenticado = token_data.get("sub")
    resposta = AccountManager.ler_ficheiro(email_autenticado, ficheiro_id)

    if resposta['status'] == 'sucesso':
        Logger.registar_log("ler_ficheiro", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    else:
        Logger.registar_log("ler_ficheiro", "erro", ip=ip, email=email_autenticado, detalhes=resposta['mensagem'])
    return resposta

@app.get("/ficheiros/{ficheiro_id}/pedido-modificar")
async def pedido_modificar_ficheiro(request: Request,ficheiro_id: str, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    email_autenticado = token_data.get("sub")
    resposta = AccountManager.pedido_modificar_ficheiro(email_autenticado, ficheiro_id)

    if resposta['status'] == 'sucesso':
        Logger.registar_log("pedido_modificar_ficheiro", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    else:
        Logger.registar_log("pedido_modificar_ficheiro", "erro", ip=ip, email=email_autenticado, detalhes=resposta['mensagem'])
    return resposta

@app.put("/ficheiros/{ficheiro_id}/modificar", response_model=dict)
async def modificar_ficheiro(request: Request, dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    # Validar os dados recebidos
    if not dados.conteudo_cifrado or not dados.iv or not dados.tag or not dados.recurso_id:
        return {"status": "erro", "mensagem": "Dados incompletos para modificar o ficheiro"}
    
    email_autenticado = token_data.get("sub")
    resposta = AccountManager.modificar_ficheiro(email_autenticado, dados.recurso_id, dados.conteudo_cifrado, dados.iv, dados.tag)

    if resposta['status'] == 'sucesso':
        Logger.registar_log("modificar_ficheiro", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    else:
        Logger.registar_log("modificar_ficheiro", "erro", ip=ip, email=email_autenticado, detalhes=resposta['mensagem'])
    return resposta

@app.get("/ficheiros/{ficheiro_id}/pedido-adicionar")
async def pedido_adicionar_ao_ficheiro(request: Request,ficheiro_id: str, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    email_autenticado = token_data.get("sub")
    resposta = AccountManager.pedido_adicionar_ao_ficheiro(email_autenticado, ficheiro_id)

    if resposta['status'] == 'sucesso':
        Logger.registar_log("pedido_adicionar_ao_ficheiro", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    else:
        Logger.registar_log("pedido_adicionar_ao_ficheiro", "erro", ip=ip, email=email_autenticado, detalhes=resposta['mensagem'])
    return resposta

@app.put("/ficheiros/{ficheiro_id}/adicionar")
async def adicionar_ao_ficheiro(request: Request, dados: Request_Schema, token_data:dict=Depends(verificar_access_token)):
    ip = request.client.host

    # Validar os dados recebidos
    if not dados.conteudo_cifrado or not dados.iv or not dados.tag or not dados.recurso_id:
        return {"status": "erro", "mensagem": "Dados incompletos para modificar o ficheiro"}
    
    email_autenticado = token_data.get("sub")
    resposta = AccountManager.adicionar_ao_ficheiro(email_autenticado, dados.recurso_id, dados.conteudo_cifrado, dados.iv, dados.tag)

    if resposta['status'] == 'sucesso':
        Logger.registar_log("adicionar_ao_ficheiro", "sucesso", ip=ip, email=email_autenticado, detalhes="Sem detalhes")
    else:
        Logger.registar_log("adicionar_ao_ficheiro", "erro", ip=ip, email=email_autenticado, detalhes=resposta['mensagem'])
    return resposta

##########
# oauth2 #
##########

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

@app.get("/auth/google/login")
async def login_google():
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        "response_type=code&"
        f"redirect_uri={REDIRECT_URI}&"
        "scope=openid%20email%20profile&"
        "access_type=offline&"
        "prompt=consent"
    )
    return {"auth_url": auth_url}

@app.get("/auth/google/callback")
async def auth_google_callback(code: str = Query(None)):
    code_html = ""
    if code:
        code_html = f"""
            <div class="code-box" id="code-box">{code}</div>
            <button class="copy-btn" onclick="copyCode()">Copiar código</button>
            <script>
                function copyCode() {{
                    const codeBox = document.getElementById('code-box');
                    navigator.clipboard.writeText(codeBox.textContent);
                    const btn = document.querySelector('.copy-btn');
                    btn.textContent = 'Copiado!';
                    setTimeout(() => btn.textContent = 'Copiar código', 1500);
                }}
            </script>
        """
    else:
        code_html = "<div class='no-code'>Nenhum código encontrado na URL.</div>"

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
        <meta charset="UTF-8">
        <title>Secure Vault - Autenticação Google</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                font-family: 'Segoe UI', Arial, sans-serif;
                color: #fff;
                min-height: 100vh;
                margin: 0;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .container {{
                background: rgba(28, 41, 61, 0.92);
                padding: 2.5rem 2rem;
                border-radius: 16px;
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
                text-align: center;
                max-width: 400px;
                width: 100%;
            }}
            .icon {{
                font-size: 3.5rem;
                margin-bottom: 0.5rem;
            }}
            h2 {{
                margin: 0.4em 0 0.2em 0;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            .code-label {{
                margin-top: 1.5em;
                font-size: 1.1rem;
                color: #b6cafb;
            }}
            .code-box {{
                background: #22355d;
                color: #fff;
                padding: 0.8em 1em;
                border-radius: 8px;
                font-family: 'Fira Mono', 'Consolas', monospace;
                font-size: 1.1rem;
                margin: 1em 0 1.2em 0;
                word-break: break-all;
                letter-spacing: 1px;
                user-select: all;
            }}
            .copy-btn {{
                background: #2a5298;
                color: #fff;
                border: none;
                padding: 0.6em 1.4em;
                border-radius: 6px;
                font-size: 1.05rem;
                cursor: pointer;
                transition: background 0.2s;
            }}
            .copy-btn:hover {{
                background: #1e3c72;
            }}
            .no-code {{
                margin: 2em 0 1em 0;
                color: #ffbaba;
                font-size: 1.1rem;
            }}
            p {{
                margin-top: 2em;
                font-size: 1.03rem;
                color: #b6cafb;
            }}
            @media (max-width: 480px) {{
                .container {{
                    padding: 1.3rem 0.5rem;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">🔒</div>
            <h2>Autenticação concluída!</h2>
            <div class="code-label">Copia este código e cola no Secure Vault CLI:</div>
            {code_html}
            <p>Podes fechar esta janela.<br>
            <span style="font-size:0.96em;">Obrigado por usares o Secure Vault!</span></p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)

@app.post("/auth/google/token")
async def google_token_exchange(code: str):
    try:
        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            timeout=10
        )
        token_data = token_response.json()
        if "access_token" not in token_data:
            raise HTTPException(status_code=400, detail=token_data)

        user_info = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
            timeout=10
        ).json()

        email = user_info.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Email não encontrado na resposta do Google.")

        user_id = DBManager.obter_id_from_email_db(email)
        if not user_id:
            raise HTTPException(status_code=404, detail="Utilizador não encontrado na base de dados.")

        access_token = criar_token_dados(data={"sub": email, "user_id": user_id})
        refresh_token = criar_refresh_token(data={"sub": email, "user_id": user_id})

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))