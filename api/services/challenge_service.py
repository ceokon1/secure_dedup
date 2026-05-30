from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from api.core.config import get_settings
from api.models.user import User
from api.repositories.challenge_repo import ChallengeRepository
from api.repositories.file_repo import FileRepository
from api.schemas.files import ChallengeCreateResponse


class ChallengeService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()
        self.file_repo = FileRepository(db)
        self.challenge_repo = ChallengeRepository(db)

    def create(self, user: User, tag_hex: str) -> ChallengeCreateResponse:
        file = self.file_repo.get_by_tag(tag_hex)
        if file is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File tag not found")

        nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.settings.challenge_ttl_seconds)
        challenge = self.challenge_repo.create(
            user_id=user.id,
            tag_hex=tag_hex,
            nonce_b64=nonce_b64,
            context="pow-claim-v1",
            expires_at=expires_at,
        )
        self.db.commit()
        self.db.refresh(challenge)
        return ChallengeCreateResponse(nonce_b64=challenge.nonce_b64, context=challenge.context)
