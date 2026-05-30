from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    enc_urk_b64: str
    enc_urk_nonce_b64: str
    kek_salt_b64: str


class RegisterResponse(BaseModel):
    user_id: str
    message: str = "Registration successful"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str


class BootstrapResponse(BaseModel):
    user_id: str
    email: EmailStr
    enc_urk_b64: str
    enc_urk_nonce_b64: str
    kek_salt_b64: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)
    enc_urk_b64: str
    enc_urk_nonce_b64: str
    kek_salt_b64: str


class ChangePasswordResponse(BaseModel):
    message: str = "Password changed successfully"
