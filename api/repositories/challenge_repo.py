from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.models.pow_challenge import PowChallenge


class ChallengeRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        user_id: str,
        tag_hex: str,
        nonce_b64: str,
        context: str,
        expires_at: datetime,
    ) -> PowChallenge:
        challenge = PowChallenge(
            user_id=user_id,
            tag_hex=tag_hex,
            nonce_b64=nonce_b64,
            context=context,
            expires_at=expires_at,
        )
        self.db.add(challenge)
        return challenge

    def get_latest_active(self, *, user_id: str, tag_hex: str, now: datetime) -> PowChallenge | None:
        stmt = (
            select(PowChallenge)
            .where(
                PowChallenge.user_id == user_id,
                PowChallenge.tag_hex == tag_hex,
                PowChallenge.used_at.is_(None),
                PowChallenge.expires_at >= now,
            )
            .order_by(PowChallenge.created_at.desc())
        )
        return self.db.execute(stmt).scalars().first()
