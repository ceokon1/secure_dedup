from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, or_

from api.db.session import SessionLocal
from api.models.pow_challenge import PowChallenge


def cleanup_expired_challenges() -> int:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        stmt = delete(PowChallenge).where(
            or_(
                PowChallenge.expires_at < now,
                PowChallenge.used_at.is_not(None),
            )
        )
        result = db.execute(stmt)
        db.commit()
        return int(result.rowcount or 0)
