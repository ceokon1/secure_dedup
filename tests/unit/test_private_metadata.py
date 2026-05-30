from __future__ import annotations

from client_cli.crypto.private_metadata import decrypt_display_name, encrypt_display_name
from client_cli.crypto.root_key import generate_root_key


def test_encrypt_and_decrypt_display_name_round_trip() -> None:
    root_key = generate_root_key()
    encrypted = encrypt_display_name(root_key, "thesis-final.pdf")
    assert encrypted.ciphertext_b64
    assert encrypted.nonce_b64
    assert decrypt_display_name(root_key, encrypted.ciphertext_b64, encrypted.nonce_b64) == "thesis-final.pdf"
