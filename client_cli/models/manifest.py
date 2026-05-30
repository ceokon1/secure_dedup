from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Manifest:
    version: str
    aead_alg: str
    nonce_b64: str
    file_hash_hex: str
    tag_hex: str
    pk_pow_b64: str
    plaintext_size: int
    ciphertext_size: int
    ciphertext_sha256_hex: str
    mime_type: str = "application/octet-stream"
    original_filename: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Manifest":
        return cls(
            version=str(data["version"]),
            aead_alg=str(data["aead_alg"]),
            nonce_b64=str(data["nonce_b64"]),
            file_hash_hex=str(data["file_hash_hex"]),
            tag_hex=str(data["tag_hex"]),
            pk_pow_b64=str(data["pk_pow_b64"]),
            plaintext_size=int(data["plaintext_size"]),
            ciphertext_size=int(data["ciphertext_size"]),
            ciphertext_sha256_hex=str(data["ciphertext_sha256_hex"]),
            mime_type=str(data.get("mime_type", "application/octet-stream")),
            original_filename=data.get("original_filename"),
        )

    def aad_payload(self) -> Dict[str, Any]:
        """
        Only the fields that must be authenticated as AEAD AAD.
        Fields derived after encryption, like ciphertext_sha256_hex, are excluded.
        """
        return {
            "version": self.version,
            "aead_alg": self.aead_alg,
            "file_hash_hex": self.file_hash_hex,
            "tag_hex": self.tag_hex,
            "pk_pow_b64": self.pk_pow_b64,
            "plaintext_size": self.plaintext_size,
            "mime_type": self.mime_type,
            "original_filename": self.original_filename,
        }
