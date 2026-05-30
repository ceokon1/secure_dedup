from __future__ import annotations

import hashlib
import json
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client_cli.crypto.password_kdf import b64e


def derive_signing_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def get_public_key_bytes(signing_key: Ed25519PrivateKey) -> bytes:
    return signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def get_public_key_b64(signing_key: Ed25519PrivateKey) -> str:
    return b64e(get_public_key_bytes(signing_key))


def get_tag_hex_from_public_key(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()


def derive_pow_material(seed: bytes) -> Tuple[Ed25519PrivateKey, bytes, str, str]:
    signing_key = derive_signing_key_from_seed(seed)
    public_key_bytes = get_public_key_bytes(signing_key)
    public_key_b64 = b64e(public_key_bytes)
    tag_hex = get_tag_hex_from_public_key(public_key_bytes)
    return signing_key, public_key_bytes, public_key_b64, tag_hex


def build_claim_message(
    *,
    context: str,
    user_id: str,
    tag_hex: str,
    nonce_b64: str,
) -> bytes:
    payload = {
        "context": context,
        "nonce_b64": nonce_b64,
        "tag_hex": tag_hex,
        "user_id": user_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_message_b64(signing_key: Ed25519PrivateKey, message: bytes) -> str:
    signature = signing_key.sign(message)
    return b64e(signature)
