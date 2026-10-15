import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.environ.get("JWT_SECRET") or os.environ.get("SECRET_KEY") or "default-secret-key-change-in-production"
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

router = APIRouter(prefix="/api", tags=["auth"])

USERS_DB = {
    "admin": {
        "username": "admin",
        "email": "admin@example.com",
        "hashed_password": pwd_context.hash("admin123"),
    },
    "user": {
        "username": "user",
        "email": "user@example.com",
        "hashed_password": pwd_context.hash("user123"),
    },
}


class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def find_user(identifier: str) -> Optional[dict]:
    identifier_lower = identifier.lower()
    for user in USERS_DB.values():
        if user["username"].lower() == identifier_lower or user["email"].lower() == identifier_lower:
            return user
    return None


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest):
    identifier = request.username or request.email
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is required",
        )

    user = find_user(identifier)
    if not user or not pwd_context.verify(request.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user["username"], "email": user["email"]})
    return TokenResponse(access_token=access_token, token_type="bearer")
