import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Request
from pydantic import BaseModel
import jwt
from passlib.context import CryptContext

SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(tags=["auth"])

DEFAULT_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
DEFAULT_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

USERS_DB = {
    DEFAULT_USERNAME: {
        "id": 1,
        "username": DEFAULT_USERNAME,
        "email": f"{DEFAULT_USERNAME}@example.com",
        "hashed_password": pwd_context.hash(DEFAULT_PASSWORD),
        "is_active": True,
    }
}

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Optional[dict] = None

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/api/login", response_model=TokenResponse)
@router.post("/login", response_model=TokenResponse)
async def login(request: Request):
    username = None
    email = None
    password = None

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            username = body.get("username")
            email = body.get("email")
            password = body.get("password")
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body")
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form = await request.form()
        username = form.get("username")
        email = form.get("email")
        password = form.get("password")
    else:
        try:
            body = await request.json()
            username = body.get("username")
            email = body.get("email")
            password = body.get("password")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported Content-Type or invalid request payload"
            )

    identifier = username or email
    if not identifier or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email and password are required"
        )

    user = None
    for u in USERS_DB.values():
        if u["username"] == identifier or u["email"] == identifier:
            user = u
            break

    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )

    access_token = create_access_token(data={"sub": user["username"], "user_id": user["id"]})

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
        }
    )
