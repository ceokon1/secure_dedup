from __future__ import annotations

import json
import mimetypes
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client_cli.crypto.file_hash import sha256_bytes_hex
from client_cli.crypto.password_kdf import b64d, b64e
from client_cli.models.manifest import Manifest


FILE_AEAD_ALG = "AES-256-GCM"
FILE_NONCE_LENGTH = 12
FILE_FORMAT_VERSION = "1"


def _build_aad(manifest: Manifest) -> bytes:
    return json.dumps(
        manifest.aad_payload(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encrypt_file(
    path: str | Path,
    *,
    encryption_key: bytes,
    file_hash_hex: str,
    tag_hex: str,
    pk_pow_b64: str,
    original_filename: str | None = None,
) -> tuple[bytes, Manifest]:
    file_path = Path(path)
    plaintext = file_path.read_bytes()

    computed_hash = sha256_bytes_hex(plaintext)
    if computed_hash != file_hash_hex:
        raise ValueError("File hash changed between hashing and encryption")

    nonce = os.urandom(FILE_NONCE_LENGTH)
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if not mime_type:
        mime_type = "application/octet-stream"

    manifest_stub = Manifest(
        version=FILE_FORMAT_VERSION,
        aead_alg=FILE_AEAD_ALG,
        nonce_b64=b64e(nonce),
        file_hash_hex=file_hash_hex,
        tag_hex=tag_hex,
        pk_pow_b64=pk_pow_b64,
        plaintext_size=len(plaintext),
        ciphertext_size=0,
        ciphertext_sha256_hex="",
        mime_type=mime_type,
        original_filename=original_filename,
    )

    aad = _build_aad(manifest_stub)
    ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, aad)
    ciphertext_sha256_hex = sha256_bytes_hex(ciphertext)

    final_manifest = Manifest(
        version=manifest_stub.version,
        aead_alg=manifest_stub.aead_alg,
        nonce_b64=manifest_stub.nonce_b64,
        file_hash_hex=manifest_stub.file_hash_hex,
        tag_hex=manifest_stub.tag_hex,
        pk_pow_b64=manifest_stub.pk_pow_b64,
        plaintext_size=manifest_stub.plaintext_size,
        ciphertext_size=len(ciphertext),
        ciphertext_sha256_hex=ciphertext_sha256_hex,
        mime_type=manifest_stub.mime_type,
        original_filename=manifest_stub.original_filename,
    )
    return ciphertext, final_manifest


def decrypt_ciphertext(ciphertext: bytes, *, encryption_key: bytes, manifest: Manifest) -> bytes:
    if manifest.aead_alg != FILE_AEAD_ALG:
        raise ValueError(f"Unsupported AEAD algorithm: {manifest.aead_alg}")

    computed_cipher_hash = sha256_bytes_hex(ciphertext)
    if computed_cipher_hash != manifest.ciphertext_sha256_hex:
        raise ValueError("Ciphertext hash mismatch")

    if len(ciphertext) != manifest.ciphertext_size:
        raise ValueError("Ciphertext size mismatch")

    nonce = b64d(manifest.nonce_b64)
    aad = _build_aad(manifest)
    plaintext = AESGCM(encryption_key).decrypt(nonce, ciphertext, aad)

    if len(plaintext) != manifest.plaintext_size:
        raise ValueError("Plaintext size mismatch after decryption")

    computed_file_hash = sha256_bytes_hex(plaintext)
    if computed_file_hash != manifest.file_hash_hex:
        raise ValueError("Plaintext hash mismatch after decryption")

    return plaintext
