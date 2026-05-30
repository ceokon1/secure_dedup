from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


HEX64 = 64


class ManifestSchema(BaseModel):
    version: str
    aead_alg: str
    nonce_b64: str
    file_hash_hex: str = Field(min_length=HEX64, max_length=HEX64)
    tag_hex: str = Field(min_length=HEX64, max_length=HEX64)
    pk_pow_b64: str
    plaintext_size: int = Field(ge=0)
    ciphertext_size: int = Field(ge=0)
    ciphertext_sha256_hex: str = Field(min_length=HEX64, max_length=HEX64)
    mime_type: str = "application/octet-stream"
    original_filename: Optional[str] = None

    @field_validator("file_hash_hex", "tag_hex", "ciphertext_sha256_hex")
    @classmethod
    def _validate_hex(cls, value: str) -> str:
        if len(value) != HEX64:
            raise ValueError("expected 64 hex characters")
        int(value, 16)
        return value.lower()


class UploadInitRequest(BaseModel):
    tag_hex: str = Field(min_length=HEX64, max_length=HEX64)
    pk_pow_b64: str
    manifest: ManifestSchema
    display_name: Optional[str] = None


class UploadInitResponse(BaseModel):
    session_id: str
    upload_url: str


class UploadCompleteRequest(BaseModel):
    session_id: str
    tag_hex: str = Field(min_length=HEX64, max_length=HEX64)
    wrapped_kf_b64: str
    wk_nonce_b64: str
    manifest: ManifestSchema
    enc_display_name_b64: str
    display_name_nonce_b64: str
    display_name: Optional[str] = None


class UploadCompleteResponse(BaseModel):
    file_id: str
    message: str
