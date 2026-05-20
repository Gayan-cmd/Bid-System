from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_role
from app.core.security import create_access_token, hash_password, verify_password
from app.db.engine import get_db
from app.models.user import User, UserRole
from app.schemas.auth import LoginRequest, PublishKeysRequest, RegisterRequest, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: Annotated[AsyncSession, Depends(get_db)]):
    """Register a new bidder. Keys can be published separately after key generation."""
    # Check duplicate email
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        name=payload.name,
        role=UserRole.BIDDER,
        hashed_password=hash_password(payload.password),
        ecdsa_pubkey=payload.ecdsa_pubkey,
        ecdh_pubkey=payload.ecdh_pubkey,
        identity_cipher=payload.identity_cipher,
    )
    db.add(user)
    await db.flush()

    token = create_access_token({"sub": str(user.id), "role": user.role.value, "email": user.email})
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    token = create_access_token({"sub": str(user.id), "role": user.role.value, "email": user.email})
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
async def me(current_user: Annotated[User, Depends(get_current_user)]):
    return UserOut.model_validate(current_user)


@router.put("/keys", response_model=UserOut)
async def publish_keys(
    payload: PublishKeysRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Upload/update the user's ECC public keys after in-browser key generation."""
    current_user.ecdsa_pubkey = payload.ecdsa_pubkey
    current_user.ecdh_pubkey = payload.ecdh_pubkey
    db.add(current_user)
    await db.flush()
    return UserOut.model_validate(current_user)
