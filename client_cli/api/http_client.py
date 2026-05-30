from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx


class APIError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class APIClient:
    """
    Minimal client for the FastAPI backend.

    Important contract notes:
    - file names are encrypted client-side per user before they reach the API;
      the API stores them on the user_files relation, not on the shared file object.
    - password changes re-wrap the same URK with a new KEK derived from the new password.
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_seconds = timeout_seconds
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout_seconds,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "APIClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def set_token(self, token: str) -> None:
        self.token = token

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _handle_response(self, response: httpx.Response) -> Any:
        if response.is_success:
            if not response.content:
                return {}
            ctype = response.headers.get("content-type", "")
            if "application/json" in ctype:
                return response.json()
            return response.content

        message = None
        try:
            data = response.json()
            if isinstance(data, dict):
                message = data.get("detail") or data.get("message")
        except Exception:
            message = None

        if not message:
            message = response.text.strip() or f"HTTP {response.status_code}"

        raise APIError(message, status_code=response.status_code)

    def _get(self, path: str) -> Any:
        response = self._client.get(path, headers=self._headers)
        return self._handle_response(response)

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        response = self._client.post(path, json=payload, headers=self._headers)
        return self._handle_response(response)

    def _delete(self, path: str) -> Any:
        response = self._client.delete(path, headers=self._headers)
        return self._handle_response(response)

    def _rewrite_presigned_url(self, url: str) -> str:
        override_base = os.getenv("SECURE_DEDUP_PRESIGNED_URL_BASE", "").strip()
        if not override_base:
            return url

        original = urlsplit(url)
        override = urlsplit(override_base)
        if not override.scheme or not override.netloc:
            raise APIError(
                "SECURE_DEDUP_PRESIGNED_URL_BASE must include scheme and host, for example http://minio:9000"
            )

        return urlunsplit(
            (
                override.scheme,
                override.netloc,
                original.path,
                original.query,
                original.fragment,
            )
        )

    def register(
        self,
        *,
        email: str,
        password: str,
        enc_urk_b64: str,
        enc_urk_nonce_b64: str,
        kek_salt_b64: str,
    ) -> Dict[str, Any]:
        return self._post(
            "/auth/register",
            {
                "email": email,
                "password": password,
                "enc_urk_b64": enc_urk_b64,
                "enc_urk_nonce_b64": enc_urk_nonce_b64,
                "kek_salt_b64": kek_salt_b64,
            },
        )

    def login(self, *, email: str, password: str) -> Dict[str, Any]:
        return self._post("/auth/login", {"email": email, "password": password})

    def get_bootstrap(self) -> Dict[str, Any]:
        return self._get("/auth/me/bootstrap")

    def change_password(
        self,
        *,
        current_password: str,
        new_password: str,
        enc_urk_b64: str,
        enc_urk_nonce_b64: str,
        kek_salt_b64: str,
    ) -> Dict[str, Any]:
        return self._post(
            "/auth/change-password",
            {
                "current_password": current_password,
                "new_password": new_password,
                "enc_urk_b64": enc_urk_b64,
                "enc_urk_nonce_b64": enc_urk_nonce_b64,
                "kek_salt_b64": kek_salt_b64,
            },
        )

    def check_tag(self, *, tag_hex: str) -> Dict[str, Any]:
        return self._post("/files/check", {"tag_hex": tag_hex})

    def create_challenge(self, *, tag_hex: str) -> Dict[str, Any]:
        return self._post("/files/challenge", {"tag_hex": tag_hex})

    def claim_existing(
        self,
        *,
        tag_hex: str,
        wrapped_kf_b64: str,
        wk_nonce_b64: str,
        signature_b64: str,
        enc_display_name_b64: str,
        display_name_nonce_b64: str,
    ) -> Dict[str, Any]:
        return self._post(
            "/files/claim",
            {
                "tag_hex": tag_hex,
                "wrapped_kf_b64": wrapped_kf_b64,
                "wk_nonce_b64": wk_nonce_b64,
                "signature_b64": signature_b64,
                "enc_display_name_b64": enc_display_name_b64,
                "display_name_nonce_b64": display_name_nonce_b64,
            },
        )

    def init_upload(
        self,
        *,
        tag_hex: str,
        pk_pow_b64: str,
        manifest: Dict[str, Any],
        display_name: str | None = None,
    ) -> Dict[str, Any]:
        return self._post(
            "/files/upload/init",
            {
                "tag_hex": tag_hex,
                "pk_pow_b64": pk_pow_b64,
                "manifest": manifest,
                "display_name": display_name,
            },
        )

    def upload_presigned_bytes(
        self,
        *,
        upload_url: str,
        payload: bytes,
        content_type: str = "application/octet-stream",
    ) -> None:
        upload_url = self._rewrite_presigned_url(upload_url)
        response = httpx.put(
            upload_url,
            content=payload,
            headers={"Content-Type": content_type},
            timeout=self.timeout_seconds,
            follow_redirects=True,
        )
        if not response.is_success:
            raise APIError(
                f"Presigned upload failed: {response.status_code} {response.text.strip()}",
                status_code=response.status_code,
            )

    def complete_upload(
        self,
        *,
        session_id: str,
        tag_hex: str,
        wrapped_kf_b64: str,
        wk_nonce_b64: str,
        manifest: Dict[str, Any],
        enc_display_name_b64: str,
        display_name_nonce_b64: str,
        display_name: str | None = None,
    ) -> Dict[str, Any]:
        return self._post(
            "/files/upload/complete",
            {
                "session_id": session_id,
                "tag_hex": tag_hex,
                "wrapped_kf_b64": wrapped_kf_b64,
                "wk_nonce_b64": wk_nonce_b64,
                "manifest": manifest,
                "enc_display_name_b64": enc_display_name_b64,
                "display_name_nonce_b64": display_name_nonce_b64,
                "display_name": display_name,
            },
        )

    def init_download(self, *, file_id: str) -> Dict[str, Any]:
        return self._post("/files/download/init", {"file_id": file_id})

    def download_presigned_bytes(self, *, download_url: str) -> bytes:
        download_url = self._rewrite_presigned_url(download_url)
        response = httpx.get(download_url, timeout=self.timeout_seconds, follow_redirects=True)
        if not response.is_success:
            raise APIError(
                f"Presigned download failed: {response.status_code} {response.text.strip()}",
                status_code=response.status_code,
            )
        return response.content

    def list_files(self) -> List[Dict[str, Any]]:
        data = self._get("/files")
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "items" in data and isinstance(data["items"], list):
            return data["items"]
        raise APIError("Unexpected response shape from GET /files")

    def delete_file(self, *, file_id: str) -> Dict[str, Any]:
        return self._delete(f"/files/{file_id}")
