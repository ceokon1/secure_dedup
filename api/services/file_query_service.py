from __future__ import annotations

from sqlalchemy.orm import Session

from api.models.user import User
from api.repositories.user_file_repo import UserFileRepository
from api.schemas.files import FileListItem


class FileQueryService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_owned_files(self, user: User) -> list[FileListItem]:
        items: list[FileListItem] = []
        for user_file, file in UserFileRepository(self.db).list_for_user(user.id):
            items.append(
                FileListItem(
                    file_id=file.id,
                    enc_display_name_b64=user_file.enc_display_name_b64,
                    display_name_nonce_b64=user_file.display_name_nonce_b64,
                    tag_hex=file.tag_hex,
                    created_at=user_file.created_at,
                )
            )
        return items
