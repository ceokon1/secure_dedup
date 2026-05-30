from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.core.deps import get_current_user
from api.db.session import get_db
from api.models.user import User
from api.schemas.files import (
    ChallengeCreateRequest,
    ChallengeCreateResponse,
    ClaimFileRequest,
    ClaimFileResponse,
)
from api.services.challenge_service import ChallengeService
from api.services.claim_service import ClaimService


router = APIRouter(prefix="/files", tags=["challenges"])


@router.post("/challenge", response_model=ChallengeCreateResponse)
def create_challenge(
    payload: ChallengeCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ChallengeCreateResponse:
    return ChallengeService(db).create(current_user, payload.tag_hex)


@router.post("/claim", response_model=ClaimFileResponse)
def claim_existing_file(
    payload: ClaimFileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ClaimFileResponse:
    return ClaimService(db).claim(current_user, payload)
