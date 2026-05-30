from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.core.security import create_access_token, hash_password, require_password_strength, verify_password
from api.models.user import User
from api.repositories.user_repo import UserRepository
from api.schemas.auth import (
    BootstrapResponse,
    ChangePasswordRequest,
    ChangePasswordResponse,
    LoginRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
)
from api.services.user_key_service import UserKeyService


class AuthService:
    def __init__(self, db: Session | None) -> None:
        self.db = db

    def register(self, payload: RegisterRequest) -> RegisterResponse:
        if self.db is None:
            raise RuntimeError("Database session is required")
        users = UserRepository(self.db)
        if users.get_by_email(payload.email):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

        try:
            require_password_strength(payload.password)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

        user = users.create(
            email=payload.email,
            password_hash=hash_password(payload.password),
            enc_urk_b64=payload.enc_urk_b64,
            enc_urk_nonce_b64=payload.enc_urk_nonce_b64,
            kek_salt_b64=payload.kek_salt_b64,
        )
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
        self.db.refresh(user)
        return RegisterResponse(user_id=user.id)

    def login(self, payload: LoginRequest) -> TokenResponse:
        if self.db is None:
            raise RuntimeError("Database session is required")
        user = UserRepository(self.db).get_by_email(payload.email)
        if user is None or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        token = create_access_token(subject=user.id)
        return TokenResponse(access_token=token, user_id=user.id)

    def bootstrap(self, user: User) -> BootstrapResponse:
        return UserKeyService().bootstrap_payload(user)

    def change_password(self, user: User, payload: ChangePasswordRequest) -> ChangePasswordResponse:
        if self.db is None:
            raise RuntimeError("Database session is required")
        if not verify_password(payload.current_password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
        try:
            require_password_strength(payload.new_password)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        if payload.current_password == payload.new_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different from the current password")

        UserRepository(self.db).update_password_material(
            user,
            password_hash=hash_password(payload.new_password),
            enc_urk_b64=payload.enc_urk_b64,
            enc_urk_nonce_b64=payload.enc_urk_nonce_b64,
            kek_salt_b64=payload.kek_salt_b64,
        )
        self.db.commit()
        return ChangePasswordResponse()
