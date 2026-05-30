from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client_cli.crypto.password_kdf import b64d, b64e


WRAP_AAD = b"secure-dedup|wrapped-file-key|v1"
WRAP_NONCE_LENGTH = 12


@dataclass(frozen=True)
class WrappedFileKey:
    ciphertext_b64: str
    nonce_b64: str


def wrap_file_key(root_key: bytes, file_key: bytes) -> WrappedFileKey:
    nonce = os.urandom(WRAP_NONCE_LENGTH)
    ciphertext = AESGCM(root_key).encrypt(nonce, file_key, WRAP_AAD)
    return WrappedFileKey(ciphertext_b64=b64e(ciphertext), nonce_b64=b64e(nonce))


def unwrap_file_key(root_key: bytes, wrapped_kf_b64: str, wk_nonce_b64: str) -> bytes:
    nonce = b64d(wk_nonce_b64)
    ciphertext = b64d(wrapped_kf_b64)
    return AESGCM(root_key).decrypt(nonce, ciphertext, WRAP_AAD)
