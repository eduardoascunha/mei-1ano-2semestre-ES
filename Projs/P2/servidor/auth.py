from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, Body, HTTPException
import os
from dotenv import load_dotenv
import redis

load_dotenv()
SECRET_KEY = os.getenv("JWT_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_HOURS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

redis_client = redis.Redis(host=os.getenv("REDIS_HOST"), port=os.getenv("REDIS_PORT"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def criar_token_dados(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def criar_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=REFRESH_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verificar_access_token(token: str = Depends(oauth2_scheme)):
    if redis_client.get(f"blacklist_access_{token}"):
        raise HTTPException(status_code=401, detail="Access Token em Blacklist")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # garante que é mesmo um access token
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Token não é um access token")
        
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Access Token inválido")
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access Token expirado")
    except JWTError:
        raise HTTPException(status_code=401, detail="Access Token inválido")

def verificar_refresh_token(refresh_token: str = Body(..., embed=True)):
    if redis_client.get(f"blacklist_refresh_{refresh_token}"):
        raise HTTPException(status_code=401, detail="Refresh Token em Blacklist")
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        # garante que é mesmo um refresh token
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Token não é um refresh token")
        
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Refresh token inválido")
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expirado")
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token inválido")

def add_blacklist(token: str, token_type: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp_timestamp = payload.get("exp")
        if exp_timestamp:
            ttl = exp_timestamp - int(datetime.utcnow().timestamp()) # guarda com ttl igual à validade do token
            if ttl > 0:
                # prefixo diff para cada tipo de token
                redis_client.setex(f"blacklist_{token_type}_{token}", ttl, "true")
    except JWTError:
        pass  
