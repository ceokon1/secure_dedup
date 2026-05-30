from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.core.config import get_settings
from api.core.logging import configure_logging
from api.db.init_db import init_db
from api.integrations.minio_client import get_minio_client
from api.routers import auth, challenges, downloads, files, health, uploads


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()
    if settings.auto_create_bucket:
        try:
            get_minio_client().ensure_bucket()
        except Exception as exc:  # pragma: no cover - environment-specific
            # The API can still start, but upload/download endpoints will fail until MinIO is reachable.
            print(f"[startup] warning: failed to ensure MinIO bucket: {exc}")
    yield


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(uploads.router)
app.include_router(downloads.router)
app.include_router(challenges.router)
