from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.db.base import Base

if TYPE_CHECKING:
    from api.models.file import File
    from api.models.user import User


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserFile(Base):
    __tablename__ = "user_files"
    __table_args__ = (
        UniqueConstraint("user_id", "file_id", name="uq_user_file_user_id_file_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True, nullable=False)
    wrapped_kf_b64: Mapped[str] = mapped_column(Text, nullable=False)
    wk_nonce_b64: Mapped[str] = mapped_column(Text, nullable=False)
    enc_display_name_b64: Mapped[str | None] = mapped_column(Text, nullable=True)
    display_name_nonce_b64: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="user_files")
    file: Mapped["File"] = relationship(back_populates="user_files")
