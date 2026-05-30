from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from api.models.file import File


class FileRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, file_id: str) -> File | None:
        stmt = select(File).where(File.id == file_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_tag(self, tag_hex: str) -> File | None:
        stmt = select(File).where(File.tag_hex == tag_hex)
        return self.db.execute(stmt).scalar_one_or_none()

    def create(
        self,
        *,
        tag_hex: str,
        pk_pow_b64: str,
        object_key: str,
        manifest_json: dict[str, Any],
        display_name: str | None,
        status: str = "READY",
    ) -> File:
        file = File(
            tag_hex=tag_hex,
            pk_pow_b64=pk_pow_b64,
            object_key=object_key,
            manifest_json=manifest_json,
            display_name=display_name,
            status=status,
        )
        self.db.add(file)
        return file

    def delete(self, file: File) -> None:
        self.db.delete(file)
