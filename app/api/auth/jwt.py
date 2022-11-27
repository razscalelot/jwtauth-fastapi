from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from core.security import settings
from typing import Any
from services.user_service import UserService
from core.security import create_access_token, create_refresh_token
from schemas.auth_schema import TokenSchema, TokenPayload
from schemas.user_schema import UserOut
from models.user_model import User
from api.deps.user_deps import get_current_user
from jose import jwt
from pydantic import ValidationError


auth_router = APIRouter()

@auth_router.post("/login", summary="Create access and refresh tokens for user", response_model=TokenSchema)
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Any:
    user = await UserService.authenticate(email=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password."
        )

    return {
        "access_token": create_access_token(user.userid),
        "refresh_token": create_refresh_token(user.userid)
    }


@auth_router.post("/access-token", summary="Test if the access token is valid", response_model=UserOut)
async def test_token(user: User = Depends(get_current_user)):
    return user


@auth_router.post("/refresh-token", summary="Refresh token", response_model=TokenSchema)
async def refresh_token(refresh_token: str = Body(...)):
    try:
        payload = jwt.decode(
            refresh_token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
        if datetime.fromtimestamp(token_data.exp) < datetime.now():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except (jwt.JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await UserService.get_user_by_id(token_data.sub)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not find user",
        )
    
    return {
        "access_token": create_access_token(user.userid),
        "refresh_token": create_refresh_token(user.userid)
    }
