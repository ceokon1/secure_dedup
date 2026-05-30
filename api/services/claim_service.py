from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from api.crypto.verify import build_claim_message, verify_claim_signature
from api.models.user import User
from api.repositories.challenge_repo import ChallengeRepository
from api.repositories.file_repo import FileRepository
from api.repositories.user_file_repo import UserFileRepository
from api.schemas.files import ClaimFileRequest, ClaimFileResponse


class ClaimService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.file_repo = FileRepository(db)
        self.challenge_repo = ChallengeRepository(db)
        self.user_file_repo = UserFileRepository(db)

    def claim(self, user: User, payload: ClaimFileRequest) -> ClaimFileResponse:
        file = self.file_repo.get_by_tag(payload.tag_hex)
        if file is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File tag not found")

        existing = self.user_file_repo.get_by_user_and_file(user.id, file.id)
        if existing is not None:
            return ClaimFileResponse(file_id=file.id, claimed=True, message="User already owns this file")

        now = datetime.now(timezone.utc)
        challenge = self.challenge_repo.get_latest_active(user_id=user.id, tag_hex=payload.tag_hex, now=now)
        if challenge is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active challenge found for this tag")

        message = build_claim_message(
            context=challenge.context,
            user_id=user.id,
            tag_hex=payload.tag_hex,
            nonce_b64=challenge.nonce_b64,
        )
        if not verify_claim_signature(
            signature_b64=payload.signature_b64,
            pk_pow_b64=file.pk_pow_b64,
            message=message,
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid proof-of-ownership signature")

        self.user_file_repo.create(
            user_id=user.id,
            file_id=file.id,
            wrapped_kf_b64=payload.wrapped_kf_b64,
            wk_nonce_b64=payload.wk_nonce_b64,
            enc_display_name_b64=payload.enc_display_name_b64,
            display_name_nonce_b64=payload.display_name_nonce_b64,
        )
        challenge.used_at = now
        self.db.commit()
        return ClaimFileResponse(file_id=file.id, claimed=True, message="Ownership claim stored")
