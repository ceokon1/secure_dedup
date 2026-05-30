from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client_cli.crypto.password_kdf import b64d, b64e, derive_kek


URK_LENGTH = 32
URK_WRAP_NONCE_LENGTH = 12
URK_AAD = b"secure-dedup|user-root-key|v1"


@dataclass(frozen=True)
class EncryptedRootKey:
    ciphertext_b64: str
    nonce_b64: str


def generate_root_key(num_bytes: int = URK_LENGTH) -> bytes:
    return os.urandom(num_bytes)


def encrypt_root_key(root_key: bytes, kek: bytes) -> EncryptedRootKey:
    nonce = os.urandom(URK_WRAP_NONCE_LENGTH)
    ciphertext = AESGCM(kek).encrypt(nonce, root_key, URK_AAD)
    return EncryptedRootKey(ciphertext_b64=b64e(ciphertext), nonce_b64=b64e(nonce))


def decrypt_root_key(enc_root_key_b64: str, nonce_b64: str, kek: bytes) -> bytes:
    ciphertext = b64d(enc_root_key_b64)
    nonce = b64d(nonce_b64)
    return AESGCM(kek).decrypt(nonce, ciphertext, URK_AAD)


def unlock_root_key_from_bootstrap(password: str, bootstrap: dict) -> bytes:
    """
    Expects bootstrap payload with:
      enc_urk_b64, enc_urk_nonce_b64, kek_salt_b64
    """
    salt = b64d(bootstrap["kek_salt_b64"])
    kek = derive_kek(password, salt)
    return decrypt_root_key(
        bootstrap["enc_urk_b64"],
        bootstrap["enc_urk_nonce_b64"],
        kek,
    )
