import os
from fastapi import APIRouter, HTTPException, status
from app.schemas.auth import LoginRequest, Token
from app.core.security import verify_password, create_access_token, get_password_hash

router = APIRouter(prefix="/api", tags=["auth"])

DEMO_USER = os.getenv("DEMO_USER", "admin")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "admin123")

# ponytail: in-memory user store for single-node demo; replace with persistent DB model when multi-user dynamic management is required
users_db = {
    DEMO_USER: {
        "username": DEMO_USER,
        "hashed_password": get_password_hash(DEMO_PASSWORD),
    }
}

@router.post("/login", response_model=Token)
async def login(credentials: LoginRequest):
    user = users_db.get(credentials.username)
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(subject=user["username"])
    return Token(access_token=access_token, token_type="bearer")
