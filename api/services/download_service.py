from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from api.models.user import User
from api.repositories.file_repo import FileRepository
from api.repositories.user_file_repo import UserFileRepository
from api.schemas.download import DownloadInitResponse
from api.schemas.upload import ManifestSchema
from api.services.storage_service import StorageService


class DownloadService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.file_repo = FileRepository(db)
        self.user_file_repo = UserFileRepository(db)
        self.storage = StorageService()

    def init_download(self, user: User, file_id: str) -> DownloadInitResponse:
        file = self.file_repo.get_by_id(file_id)
        if file is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        user_file = self.user_file_repo.get_by_user_and_file(user.id, file.id)
        if user_file is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File is not owned by the current user")

        self.storage.assert_object_exists(file.object_key)
        manifest = ManifestSchema.model_validate(file.manifest_json)
        return DownloadInitResponse(
            download_url=self.storage.create_download_url(file.object_key),
            wrapped_kf_b64=user_file.wrapped_kf_b64,
            wk_nonce_b64=user_file.wk_nonce_b64,
            manifest=manifest,
            enc_display_name_b64=user_file.enc_display_name_b64,
            display_name_nonce_b64=user_file.display_name_nonce_b64,
        )
