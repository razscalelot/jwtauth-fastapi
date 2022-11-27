from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Union, Any
from core.config import settings
from jose import jwt

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def encrypt(password: str, secret_key: str, encode=True) -> str:
    password = SHA256.new(password.encode('utf-8')).digest()  # use SHA-256 over our password to get a proper-sized AES password
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(password, AES.MODE_CBC, IV)
    padding = AES.block_size - len(secret_key) % AES.block_size  # calculate needed padding
    secret_key += str([padding]) * padding  # Python 2.x: secret_key += chr(padding) * padding
    data = IV + encryptor.encrypt(secret_key.encode('utf-8'))  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(password: str, secret_key: str, decode=True) -> bool:
    if decode:
        secret_key = base64.b64decode(secret_key.encode("latin-1"))
    password = SHA256.new(password.encode('utf-8')).digest()  # use SHA-256 over our password to get a proper-sized AES password
    IV = secret_key[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(password, AES.MODE_CBC, IV)
    data = decryptor.decrypt(secret_key[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != str([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding

def get_password(password: str) -> str:
    return password_context.hash(password)

def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)

def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, settings.ALGORITHM)
    return encoded_jwt
    

def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_REFRESH_SECRET_KEY, settings.ALGORITHM)
    return encoded_jwt