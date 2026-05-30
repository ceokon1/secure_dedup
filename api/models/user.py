from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.db.base import Base

if TYPE_CHECKING:
    from api.models.pow_challenge import PowChallenge
    from api.models.upload_session import UploadSession
    from api.models.user_file import UserFile


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    enc_urk_b64: Mapped[str] = mapped_column(Text, nullable=False)
    enc_urk_nonce_b64: Mapped[str] = mapped_column(Text, nullable=False)
    kek_salt_b64: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user_files: Mapped[list["UserFile"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    challenges: Mapped[list["PowChallenge"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    upload_sessions: Mapped[list["UploadSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")
