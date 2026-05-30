from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from api.models.user import User
from api.repositories.file_repo import FileRepository
from api.repositories.user_file_repo import UserFileRepository
from api.schemas.common import DeleteResponse
from api.services.storage_service import StorageService


class DeleteService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.file_repo = FileRepository(db)
        self.user_file_repo = UserFileRepository(db)
        self.storage = StorageService()

    def delete_owned_file(self, user: User, file_id: str) -> DeleteResponse:
        relation = self.user_file_repo.get_by_user_and_file(user.id, file_id)
        if relation is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Owned file record not found")

        self.user_file_repo.delete(relation)
        self.db.commit()

        remaining_refs = self.user_file_repo.count_for_file(file_id)
        object_deleted = False
        file = self.file_repo.get_by_id(file_id)
        if file is not None and remaining_refs == 0:
            object_deleted = self.storage.remove_object_if_exists(file.object_key)
            self.file_repo.delete(file)
            self.db.commit()

        return DeleteResponse(
            file_id=file_id,
            removed_ownership=True,
            object_deleted=object_deleted,
            message="File ownership deleted",
        )
