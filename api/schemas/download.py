from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from api.schemas.upload import ManifestSchema


class DownloadInitRequest(BaseModel):
    file_id: str


class DownloadInitResponse(BaseModel):
    download_url: str
    wrapped_kf_b64: str
    wk_nonce_b64: str
    manifest: ManifestSchema
    enc_display_name_b64: Optional[str] = None
    display_name_nonce_b64: Optional[str] = None
