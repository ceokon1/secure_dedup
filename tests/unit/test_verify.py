from __future__ import annotations

from client_cli.crypto.file_keys import derive_pow_seed
from client_cli.crypto.pow_sign import build_claim_message, derive_pow_material, sign_message_b64
from api.crypto.verify import verify_claim_signature


def test_verify_claim_signature_round_trip() -> None:
    file_key = b"y" * 32
    signing_key, _public_key_bytes, pk_pow_b64, _tag_hex = derive_pow_material(derive_pow_seed(file_key))
    message = build_claim_message(
        context="pow-claim-v1",
        user_id="user-123",
        tag_hex="ab" * 32,
        nonce_b64="bm9uY2U=",
    )
    signature_b64 = sign_message_b64(signing_key, message)
    assert verify_claim_signature(signature_b64=signature_b64, pk_pow_b64=pk_pow_b64, message=message) is True
