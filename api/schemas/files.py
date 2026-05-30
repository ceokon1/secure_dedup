from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


HEX64 = 64


class _TagModel(BaseModel):
    tag_hex: str = Field(min_length=HEX64, max_length=HEX64)

    @field_validator("tag_hex")
    @classmethod
    def _validate_tag_hex(cls, value: str) -> str:
        if len(value) != HEX64:
            raise ValueError("tag_hex must contain exactly 64 hex characters")
        int(value, 16)
        return value.lower()


class CheckTagRequest(_TagModel):
    pass


class CheckTagResponse(BaseModel):
    exists: bool
    file_id: Optional[str] = None


class ChallengeCreateRequest(_TagModel):
    pass


class ChallengeCreateResponse(BaseModel):
    nonce_b64: str
    context: str


class ClaimFileRequest(_TagModel):
    wrapped_kf_b64: str
    wk_nonce_b64: str
    signature_b64: str
    enc_display_name_b64: str
    display_name_nonce_b64: str


class ClaimFileResponse(BaseModel):
    file_id: str
    claimed: bool
    message: str


class FileListItem(BaseModel):
    file_id: str
    enc_display_name_b64: Optional[str] = None
    display_name_nonce_b64: Optional[str] = None
    tag_hex: str
    created_at: datetime
