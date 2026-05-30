from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from functools import lru_cache


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "secure-dedup-api")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    debug: bool = _env_bool("DEBUG", False)
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./secure_dedup.db")

    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_exp_minutes: int = int(os.getenv("ACCESS_TOKEN_EXP_MINUTES", "1440"))

    challenge_ttl_seconds: int = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))
    upload_session_ttl_seconds: int = int(os.getenv("UPLOAD_SESSION_TTL_SECONDS", "1800"))
    presigned_url_ttl_seconds: int = int(os.getenv("PRESIGNED_URL_TTL_SECONDS", "900"))

    minio_endpoint: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    minio_public_endpoint: str = os.getenv("MINIO_PUBLIC_ENDPOINT", os.getenv("MINIO_ENDPOINT", "localhost:9000"))
    minio_access_key: str = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    minio_secret_key: str = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    minio_bucket: str = os.getenv("MINIO_BUCKET", "secure-dedup-objects")
    minio_secure: bool = _env_bool("MINIO_SECURE", False)
    minio_public_secure: bool = _env_bool("MINIO_PUBLIC_SECURE", _env_bool("MINIO_SECURE", False))
    auto_create_bucket: bool = _env_bool("AUTO_CREATE_BUCKET", True)

    oprf_mode: str = os.getenv("OPRF_MODE", "mock")
    oprf_secret_b64: str = os.getenv(
        "OPRF_SECRET_B64",
        base64.b64encode(b"development-oprf-secret-32-bytes!!").decode("ascii"),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
