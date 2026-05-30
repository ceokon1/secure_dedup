from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.core.deps import get_current_user
from api.db.session import get_db
from api.models.user import User
from api.schemas.download import DownloadInitRequest, DownloadInitResponse
from api.services.download_service import DownloadService


router = APIRouter(prefix="/files", tags=["downloads"])


@router.post("/download/init", response_model=DownloadInitResponse)
def init_download(
    payload: DownloadInitRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DownloadInitResponse:
    return DownloadService(db).init_download(current_user, payload.file_id)
