from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_file_key(oprf_output: bytes) -> bytes:
    """
    Compresses the OPRF output into a stable 32-byte file key.

    This step is intentionally separated from the OPRF exchange so you can
    swap the OPRF implementation later without changing the rest of the CLI.
    """
    return hashlib.sha256(b"secure-dedup|file-key|v1|" + oprf_output).digest()


def _hkdf(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(key_material)


def derive_encryption_key(file_key: bytes) -> bytes:
    return _hkdf(file_key, b"secure-dedup|file-encryption|aes-gcm|v1", length=32)


def derive_pow_seed(file_key: bytes) -> bytes:
    return _hkdf(file_key, b"secure-dedup|pow-seed|ed25519|v1", length=32)
