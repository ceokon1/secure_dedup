from __future__ import annotations

from sqlalchemy import func, select

from api.db.session import SessionLocal
from api.models.file import File
from api.models.user_file import UserFile
from api.services.storage_service import StorageService


def cleanup_orphan_objects() -> int:
    storage = StorageService()
    removed = 0

    with SessionLocal() as db:
        stmt = (
            select(File)
            .outerjoin(UserFile, UserFile.file_id == File.id)
            .group_by(File.id)
            .having(func.count(UserFile.id) == 0)
        )
        orphan_files = list(db.execute(stmt).scalars().all())
        for file_model in orphan_files:
            storage.remove_object_if_exists(file_model.object_key)
            db.delete(file_model)
            removed += 1

        if removed:
            db.commit()
        return removed
