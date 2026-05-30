from __future__ import annotations

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from api.crypto.tags import b64d


def build_claim_message(*, context: str, user_id: str, tag_hex: str, nonce_b64: str) -> bytes:
    payload = {
        "context": context,
        "nonce_b64": nonce_b64,
        "tag_hex": tag_hex,
        "user_id": user_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_claim_signature(*, signature_b64: str, pk_pow_b64: str, message: bytes) -> bool:
    try:
        verify_key = Ed25519PublicKey.from_public_bytes(b64d(pk_pow_b64))
        verify_key.verify(b64d(signature_b64), message)
        return True
    except (InvalidSignature, ValueError):
        return False
