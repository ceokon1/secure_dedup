from __future__ import annotations

import uuid
from typing import Any

from fastapi import HTTPException, status

from api.core.config import get_settings
from api.integrations.minio_client import get_minio_client


class StorageService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.client = get_minio_client()

    def build_object_key(self, tag_hex: str) -> str:
        return f"objects/{tag_hex[:2]}/{tag_hex}/{uuid.uuid4().hex}.bin"

    def create_upload_url(self, object_key: str) -> str:
        return self.client.create_presigned_put_url(object_key)

    def create_download_url(self, object_key: str) -> str:
        return self.client.create_presigned_get_url(object_key)

    def assert_object_exists(self, object_key: str) -> None:
        if not self.client.object_exists(object_key):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded object not found in object storage",
            )

    def remove_object_if_exists(self, object_key: str) -> bool:
        return self.client.remove_object_if_exists(object_key)
