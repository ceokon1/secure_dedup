from __future__ import annotations

import jwt

from client_cli.crypto.file_hash import sha256_bytes_hex
from client_cli.crypto.file_keys import derive_encryption_key, derive_file_key, derive_pow_seed
from client_cli.crypto.file_encrypt import encrypt_file
from client_cli.crypto.key_wrap import wrap_file_key
from client_cli.crypto.oprf_client import MockOPRFClient
from client_cli.crypto.password_kdf import b64e
from client_cli.crypto.pow_sign import build_claim_message, derive_pow_material, sign_message_b64
from client_cli.crypto.private_metadata import decrypt_display_name, encrypt_display_name
from client_cli.crypto.root_key import encrypt_root_key, generate_root_key


def _register_and_login(client, email: str, password: str) -> dict[str, object]:
    root_key = generate_root_key()
    enc = encrypt_root_key(root_key, b"0" * 32)
    register_payload = {
        "email": email,
        "password": password,
        "enc_urk_b64": enc.ciphertext_b64,
        "enc_urk_nonce_b64": enc.nonce_b64,
        "kek_salt_b64": b64e(b"1" * 16),
    }
    r = client.post("/auth/register", json=register_payload)
    assert r.status_code == 200
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = jwt.decode(token, "test-secret-key-with-32-bytes-min!!", algorithms=["HS256"])
    return {"headers": headers, "root_key": root_key, "user_id": payload["sub"]}


def test_upload_claim_and_download_metadata_are_user_private(app_client, tmp_path) -> None:
    client = app_client.client
    fake_minio = app_client.fake_minio

    alice = _register_and_login(client, "alice2@example.com", "password123")
    bob = _register_and_login(client, "bob2@example.com", "password123")

    headers_a = alice["headers"]
    headers_b = bob["headers"]
    root_key_a = alice["root_key"]
    root_key_b = bob["root_key"]

    plaintext = b"hello secure dedup"
    file_path = tmp_path / "hello.txt"
    file_path.write_bytes(plaintext)

    file_hash_hex = sha256_bytes_hex(plaintext)
    oprf_output = MockOPRFClient().evaluate(file_hash_hex=file_hash_hex)
    file_key = derive_file_key(oprf_output)
    encryption_key = derive_encryption_key(file_key)
    signing_key, _pk_bytes, pk_pow_b64, tag_hex = derive_pow_material(derive_pow_seed(file_key))

    wrapped_a = wrap_file_key(root_key_a, file_key)
    wrapped_b = wrap_file_key(root_key_b, file_key)
    enc_name_a = encrypt_display_name(root_key_a, "alice-secret.txt")
    enc_name_b = encrypt_display_name(root_key_b, "bob-secret.txt")

    ciphertext, manifest = encrypt_file(
        file_path,
        encryption_key=encryption_key,
        file_hash_hex=file_hash_hex,
        tag_hex=tag_hex,
        pk_pow_b64=pk_pow_b64,
        original_filename=None,
    )

    init_payload = {
        "tag_hex": tag_hex,
        "pk_pow_b64": pk_pow_b64,
        "manifest": manifest.to_dict(),
    }
    r = client.post("/files/upload/init", json=init_payload, headers=headers_a)
    assert r.status_code == 200
    session_id = r.json()["session_id"]
    upload_url = r.json()["upload_url"]
    object_key = upload_url.split("https://fake-upload/", 1)[1]
    fake_minio.objects[object_key] = ciphertext

    complete_payload = {
        "session_id": session_id,
        "tag_hex": tag_hex,
        "wrapped_kf_b64": wrapped_a.ciphertext_b64,
        "wk_nonce_b64": wrapped_a.nonce_b64,
        "manifest": manifest.to_dict(),
        "enc_display_name_b64": enc_name_a.ciphertext_b64,
        "display_name_nonce_b64": enc_name_a.nonce_b64,
    }
    r = client.post("/files/upload/complete", json=complete_payload, headers=headers_a)
    assert r.status_code == 200
    file_id = r.json()["file_id"]

    r = client.post("/files/check", json={"tag_hex": tag_hex})
    assert r.status_code == 200
    assert r.json()["exists"] is True

    r = client.post("/files/challenge", json={"tag_hex": tag_hex}, headers=headers_b)
    assert r.status_code == 200
    nonce_b64 = r.json()["nonce_b64"]
    context = r.json()["context"]
    message = build_claim_message(context=context, user_id=str(bob["user_id"]), tag_hex=tag_hex, nonce_b64=nonce_b64)
    signature_b64 = sign_message_b64(signing_key, message)

    claim_payload = {
        "tag_hex": tag_hex,
        "wrapped_kf_b64": wrapped_b.ciphertext_b64,
        "wk_nonce_b64": wrapped_b.nonce_b64,
        "signature_b64": signature_b64,
        "enc_display_name_b64": enc_name_b.ciphertext_b64,
        "display_name_nonce_b64": enc_name_b.nonce_b64,
    }
    r = client.post("/files/claim", json=claim_payload, headers=headers_b)
    assert r.status_code == 200

    r = client.get("/files", headers=headers_b)
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0].get("display_name") in (None, "")
    assert decrypt_display_name(root_key_b, items[0]["enc_display_name_b64"], items[0]["display_name_nonce_b64"]) == "bob-secret.txt"
    assert decrypt_display_name(root_key_a, enc_name_a.ciphertext_b64, enc_name_a.nonce_b64) == "alice-secret.txt"

    r = client.post("/files/download/init", json={"file_id": file_id}, headers=headers_b)
    assert r.status_code == 200
    body = r.json()
    assert body["wrapped_kf_b64"] == wrapped_b.ciphertext_b64
    assert body["manifest"]["tag_hex"] == tag_hex
    assert body["manifest"]["original_filename"] is None
    assert decrypt_display_name(root_key_b, body["enc_display_name_b64"], body["display_name_nonce_b64"]) == "bob-secret.txt"
