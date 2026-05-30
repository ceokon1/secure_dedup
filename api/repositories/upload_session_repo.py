from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.models.upload_session import UploadSession


class UploadSessionRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        user_id: str,
        tag_hex: str,
        pk_pow_b64: str,
        object_key: str,
        manifest_json: dict[str, Any],
        display_name: str | None,
        expires_at: datetime,
    ) -> UploadSession:
        session = UploadSession(
            user_id=user_id,
            tag_hex=tag_hex,
            pk_pow_b64=pk_pow_b64,
            object_key=object_key,
            manifest_json=manifest_json,
            display_name=display_name,
            expires_at=expires_at,
        )
        self.db.add(session)
        return session

    def get_by_id_and_user(self, session_id: str, user_id: str) -> UploadSession | None:
        stmt = select(UploadSession).where(UploadSession.id == session_id, UploadSession.user_id == user_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def mark_completed(self, session: UploadSession) -> None:
        session.status = "COMPLETED"
        session.completed_at = datetime.now(timezone.utc)
