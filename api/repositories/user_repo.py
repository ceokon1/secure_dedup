from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.models.user import User


class UserRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email.lower())
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_id(self, user_id: str) -> User | None:
        stmt = select(User).where(User.id == user_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def create(
        self,
        *,
        email: str,
        password_hash: str,
        enc_urk_b64: str,
        enc_urk_nonce_b64: str,
        kek_salt_b64: str,
    ) -> User:
        user = User(
            email=email.lower(),
            password_hash=password_hash,
            enc_urk_b64=enc_urk_b64,
            enc_urk_nonce_b64=enc_urk_nonce_b64,
            kek_salt_b64=kek_salt_b64,
        )
        self.db.add(user)
        return user

    def update_password_material(
        self,
        user: User,
        *,
        password_hash: str,
        enc_urk_b64: str,
        enc_urk_nonce_b64: str,
        kek_salt_b64: str,
    ) -> User:
        user.password_hash = password_hash
        user.enc_urk_b64 = enc_urk_b64
        user.enc_urk_nonce_b64 = enc_urk_nonce_b64
        user.kek_salt_b64 = kek_salt_b64
        self.db.add(user)
        return user
