from __future__ import annotations

from client_cli.api.http_client import APIClient


def test_presigned_url_rewrite_disabled(monkeypatch) -> None:
    monkeypatch.delenv("SECURE_DEDUP_PRESIGNED_URL_BASE", raising=False)
    with APIClient("http://example.com") as api:
        url = "http://localhost:9000/bucket/object?X-Amz-Signature=abc123"
        assert api._rewrite_presigned_url(url) == url


def test_presigned_url_rewrite_enabled(monkeypatch) -> None:
    monkeypatch.setenv("SECURE_DEDUP_PRESIGNED_URL_BASE", "http://minio:9000")
    with APIClient("http://example.com") as api:
        url = "http://localhost:9000/secure-dedup-objects/path/file.bin?X-Amz-Signature=abc123"
        rewritten = api._rewrite_presigned_url(url)
        assert rewritten == "http://minio:9000/secure-dedup-objects/path/file.bin?X-Amz-Signature=abc123"
