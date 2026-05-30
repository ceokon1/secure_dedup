from __future__ import annotations

from datetime import timedelta
from functools import lru_cache

from minio import Minio
from minio.error import S3Error

from api.core.config import get_settings


class MinioClient:
    def __init__(self) -> None:
        settings = get_settings()
        self.bucket = settings.minio_bucket
        self._client_internal = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )
        self._client_public = Minio(
            settings.minio_public_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_public_secure,
            region="us-east-1",
        )
        self._presign_ttl = timedelta(seconds=settings.presigned_url_ttl_seconds)

    def ensure_bucket(self) -> None:
        if not self._client_internal.bucket_exists(self.bucket):
            self._client_internal.make_bucket(self.bucket)

    def create_presigned_put_url(self, object_key: str) -> str:
        return self._client_public.presigned_put_object(self.bucket, object_key, expires=self._presign_ttl)

    def create_presigned_get_url(self, object_key: str) -> str:
        return self._client_public.presigned_get_object(self.bucket, object_key, expires=self._presign_ttl)

    def object_exists(self, object_key: str) -> bool:
        try:
            self._client_internal.stat_object(self.bucket, object_key)
            return True
        except S3Error as exc:
            if exc.code in {"NoSuchKey", "NoSuchObject", "NoSuchBucket"}:
                return False
            raise

    def remove_object_if_exists(self, object_key: str) -> bool:
        try:
            self._client_internal.stat_object(self.bucket, object_key)
        except S3Error as exc:
            if exc.code in {"NoSuchKey", "NoSuchObject", "NoSuchBucket"}:
                return False
            raise
        self._client_internal.remove_object(self.bucket, object_key)
        return True


@lru_cache(maxsize=1)
def get_minio_client() -> MinioClient:
    return MinioClient()
