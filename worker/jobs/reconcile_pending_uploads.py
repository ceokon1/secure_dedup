from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from api.db.session import SessionLocal
from api.models.upload_session import UploadSession
from api.services.storage_service import StorageService


def reconcile_pending_uploads() -> int:
    now = datetime.now(timezone.utc)
    storage = StorageService()
    changed = 0

    with SessionLocal() as db:
        stmt = select(UploadSession).where(
            UploadSession.status == "PENDING",
            UploadSession.expires_at < now,
        )
        expired_sessions = list(db.execute(stmt).scalars().all())
        for session_model in expired_sessions:
            storage.remove_object_if_exists(session_model.object_key)
            session_model.status = "EXPIRED"
            changed += 1

        if changed:
            db.commit()
        return changed
