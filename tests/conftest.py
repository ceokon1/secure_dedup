from __future__ import annotations

import importlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient


class FakeMinioClient:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.bucket = "test-bucket"

    def ensure_bucket(self) -> None:
        return None

    def create_presigned_put_url(self, object_key: str) -> str:
        return f"https://fake-upload/{object_key}"

    def create_presigned_get_url(self, object_key: str) -> str:
        return f"https://fake-download/{object_key}"

    def object_exists(self, object_key: str) -> bool:
        return object_key in self.objects

    def remove_object_if_exists(self, object_key: str) -> bool:
        return self.objects.pop(object_key, None) is not None


@pytest.fixture()
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("AUTO_CREATE_BUCKET", "false")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-with-32-bytes-min!!")
    monkeypatch.setenv("OPRF_MODE", "mock")

    import api.core.config as config_mod
    config_mod.get_settings.cache_clear()

    import api.db.session as session_mod
    importlib.reload(session_mod)

    import api.db.init_db as init_db_mod
    importlib.reload(init_db_mod)

    import api.main as main_mod
    importlib.reload(main_mod)

    fake_minio = FakeMinioClient()
    monkeypatch.setattr("api.services.storage_service.get_minio_client", lambda: fake_minio)

    with TestClient(main_mod.app) as client:
        yield SimpleNamespace(client=client, fake_minio=fake_minio)
