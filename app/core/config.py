from typing import List
from pydantic import BaseSettings, AnyHttpUrl
from decouple import config

class Setttings(BaseSettings):
    APP_URI = config("APP_URI", cast=str)
    PORT: int = config("PORT", cast=int)
    API_V1_STR: str = "/api/v1"
    PASSWORD_ENCRYPTION_SECRET: str = config("PASSWORD_ENCRYPTION_SECRET", cast=str)
    JWT_SECRET_KEY: str = config("JWT_SECRET_KEY", cast=str)
    JWT_REFRESH_SECRET_KEY: str = config("JWT_REFRESH_SECRET_KEY", cast=str)
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7 # 7 Days
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    PROJECT_NAME: str = "JWTAuth"

    #Database
    MONGO_CONNECTION_STRING: str = config("MONGO_CONNECTION_STRING", cast=str)

    class Config:
        case_sensitive = True

settings = Setttings()
