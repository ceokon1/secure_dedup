from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.models.file import File
from api.models.user_file import UserFile


class UserFileRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        user_id: str,
        file_id: str,
        wrapped_kf_b64: str,
        wk_nonce_b64: str,
        enc_display_name_b64: str | None,
        display_name_nonce_b64: str | None,
    ) -> UserFile:
        user_file = UserFile(
            user_id=user_id,
            file_id=file_id,
            wrapped_kf_b64=wrapped_kf_b64,
            wk_nonce_b64=wk_nonce_b64,
            enc_display_name_b64=enc_display_name_b64,
            display_name_nonce_b64=display_name_nonce_b64,
        )
        self.db.add(user_file)
        return user_file

    def get_by_user_and_file(self, user_id: str, file_id: str) -> UserFile | None:
        stmt = select(UserFile).where(UserFile.user_id == user_id, UserFile.file_id == file_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def list_for_user(self, user_id: str) -> list[tuple[UserFile, File]]:
        stmt = (
            select(UserFile, File)
            .join(File, File.id == UserFile.file_id)
            .where(UserFile.user_id == user_id)
            .order_by(UserFile.created_at.desc())
        )
        return list(self.db.execute(stmt).all())

    def count_for_file(self, file_id: str) -> int:
        stmt = select(func.count(UserFile.id)).where(UserFile.file_id == file_id)
        value = self.db.execute(stmt).scalar_one()
        return int(value)

    def delete(self, user_file: UserFile) -> None:
        self.db.delete(user_file)
