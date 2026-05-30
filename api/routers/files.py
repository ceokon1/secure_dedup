from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.core.deps import get_current_user
from api.db.session import get_db
from api.models.user import User
from api.schemas.common import DeleteResponse
from api.schemas.files import FileListItem
from api.services.delete_service import DeleteService
from api.services.file_query_service import FileQueryService


router = APIRouter(prefix="/files", tags=["files"])


@router.get("", response_model=List[FileListItem])
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[FileListItem]:
    return FileQueryService(db).list_owned_files(current_user)


@router.delete("/{file_id}", response_model=DeleteResponse)
def delete_file(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeleteResponse:
    return DeleteService(db).delete_owned_file(current_user, file_id)
