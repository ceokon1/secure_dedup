from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.core.deps import get_current_user
from api.db.session import get_db
from api.models.user import User
from api.schemas.files import CheckTagRequest, CheckTagResponse
from api.schemas.upload import (
    UploadCompleteRequest,
    UploadCompleteResponse,
    UploadInitRequest,
    UploadInitResponse,
)
from api.services.dedup_service import DedupService
from api.services.upload_service import UploadService


router = APIRouter(prefix="/files", tags=["uploads"])


@router.post("/check", response_model=CheckTagResponse)
def check_tag(payload: CheckTagRequest, db: Session = Depends(get_db)) -> CheckTagResponse:
    return DedupService(db).check_tag(payload.tag_hex)


@router.post("/upload/init", response_model=UploadInitResponse)
def init_upload(
    payload: UploadInitRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UploadInitResponse:
    return UploadService(db).init_upload(current_user, payload)


@router.post("/upload/complete", response_model=UploadCompleteResponse)
def complete_upload(
    payload: UploadCompleteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UploadCompleteResponse:
    return UploadService(db).complete_upload(current_user, payload)
