from __future__ import annotations

import base64
import hashlib



def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))



def tag_hex_from_public_key_b64(pk_pow_b64: str) -> str:
    return hashlib.sha256(b64d(pk_pow_b64)).hexdigest()



def validate_tag_matches_public_key(tag_hex: str, pk_pow_b64: str) -> bool:
    return tag_hex_from_public_key_b64(pk_pow_b64) == tag_hex.lower()
