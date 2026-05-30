from __future__ import annotations

from client_cli.crypto.file_keys import derive_pow_seed
from client_cli.crypto.pow_sign import derive_pow_material
from api.crypto.tags import validate_tag_matches_public_key


def test_tag_matches_public_key() -> None:
    file_key = b"x" * 32
    pow_seed = derive_pow_seed(file_key)
    _signing_key, public_key_bytes, pk_pow_b64, tag_hex = derive_pow_material(pow_seed)
    assert len(public_key_bytes) == 32
    assert validate_tag_matches_public_key(tag_hex, pk_pow_b64) is True
