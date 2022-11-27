from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from uuid import UUID

class UserAuth(BaseModel):
    email: EmailStr = Field(..., description="user email")
    username: str = Field(..., min_length=5, max_length=50, description="user username")
    password: str = Field(..., min_length=5, max_length=25, description="user password")

class UserOut(BaseModel):
    userid: UUID
    username: str
    email: EmailStr
    firstname: Optional[str]
    lastname: Optional[str]
    disabled: Optional[bool]
