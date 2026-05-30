from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.core.deps import get_current_user
from api.db.session import get_db
from api.models.user import User
from api.schemas.auth import (
    BootstrapResponse,
    ChangePasswordRequest,
    ChangePasswordResponse,
    LoginRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
)
from api.services.auth_service import AuthService


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> RegisterResponse:
    return AuthService(db).register(payload)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    return AuthService(db).login(payload)


@router.get("/me/bootstrap", response_model=BootstrapResponse)
def bootstrap(current_user: User = Depends(get_current_user)) -> BootstrapResponse:
    return AuthService(None).bootstrap(current_user)


@router.post("/change-password", response_model=ChangePasswordResponse)
def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ChangePasswordResponse:
    return AuthService(db).change_password(current_user, payload)
