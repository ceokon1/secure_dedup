from __future__ import annotations

from sqlalchemy.orm import Session

from api.repositories.file_repo import FileRepository
from api.schemas.files import CheckTagResponse


class DedupService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def check_tag(self, tag_hex: str) -> CheckTagResponse:
        file = FileRepository(self.db).get_by_tag(tag_hex)
        return CheckTagResponse(exists=file is not None, file_id=file.id if file else None)
