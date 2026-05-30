from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from client_cli.crypto.password_kdf import b64d, b64e


_PRIVATE_METADATA_INFO = b"secure-dedup|private-metadata|display-name|v1"
_PRIVATE_METADATA_AAD = b"secure-dedup|private-metadata|display-name|aad|v1"
_PRIVATE_METADATA_NONCE_LENGTH = 12


@dataclass(frozen=True)
class EncryptedDisplayName:
    ciphertext_b64: str
    nonce_b64: str


def _derive_display_name_key(root_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_PRIVATE_METADATA_INFO,
    )
    return hkdf.derive(root_key)


def encrypt_display_name(root_key: bytes, display_name: str) -> EncryptedDisplayName:
    nonce = os.urandom(_PRIVATE_METADATA_NONCE_LENGTH)
    key = _derive_display_name_key(root_key)
    ciphertext = AESGCM(key).encrypt(nonce, display_name.encode("utf-8"), _PRIVATE_METADATA_AAD)
    return EncryptedDisplayName(ciphertext_b64=b64e(ciphertext), nonce_b64=b64e(nonce))


def decrypt_display_name(root_key: bytes, enc_display_name_b64: str, nonce_b64: str) -> str:
    key = _derive_display_name_key(root_key)
    nonce = b64d(nonce_b64)
    ciphertext = b64d(enc_display_name_b64)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, _PRIVATE_METADATA_AAD)
    return plaintext.decode("utf-8")
