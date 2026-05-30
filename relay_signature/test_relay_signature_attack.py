from __future__ import annotations

import os

import jwt
import pytest

from client_cli.crypto.file_encrypt import decrypt_ciphertext, encrypt_file
from client_cli.crypto.file_hash import sha256_bytes_hex
from client_cli.crypto.file_keys import derive_encryption_key, derive_file_key, derive_pow_seed
from client_cli.crypto.key_wrap import unwrap_file_key, wrap_file_key
from client_cli.crypto.oprf_client import MockOPRFClient
from client_cli.crypto.password_kdf import b64e
from client_cli.crypto.pow_sign import build_claim_message, derive_pow_material, sign_message_b64
from client_cli.crypto.private_metadata import encrypt_display_name
from client_cli.crypto.root_key import encrypt_root_key, generate_root_key
from client_cli.models.manifest import Manifest


JWT_SECRET_FOR_TESTS = "test-secret-key-with-32-bytes-min!!"


def _register_and_login(client, email: str, password: str = "password123") -> dict[str, object]:
    """Register a test user and return headers, user_id and the plaintext URK used in the test."""
    root_key = generate_root_key()
    # Existing tests use a fixed 32-byte KEK so they don't need Argon2 in integration helpers.
    enc = encrypt_root_key(root_key, b"0" * 32)
    r = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
            "enc_urk_b64": enc.ciphertext_b64,
            "enc_urk_nonce_b64": enc.nonce_b64,
            "kek_salt_b64": b64e(b"1" * 16),
        },
    )
    assert r.status_code == 200, r.text

    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = jwt.decode(token, JWT_SECRET_FOR_TESTS, algorithms=["HS256"])
    return {"headers": headers, "root_key": root_key, "user_id": payload["sub"]}


def _upload_victim_file(app_client, tmp_path):
    """Victim uploads one file. Return all cryptographic material needed to simulate a relay lab."""
    client = app_client.client
    fake_minio = app_client.fake_minio

    victim = _register_and_login(client, "relay-victim@example.com")

    plaintext = b"secret cloud document for relay signature lab"
    file_path = tmp_path / "relay-secret.txt"
    file_path.write_bytes(plaintext)

    file_hash_hex = sha256_bytes_hex(plaintext)
    oprf_output = MockOPRFClient().evaluate(file_hash_hex=file_hash_hex)
    file_key = derive_file_key(oprf_output)
    encryption_key = derive_encryption_key(file_key)
    signing_key, _pk_bytes, pk_pow_b64, tag_hex = derive_pow_material(derive_pow_seed(file_key))

    ciphertext, manifest = encrypt_file(
        file_path,
        encryption_key=encryption_key,
        file_hash_hex=file_hash_hex,
        tag_hex=tag_hex,
        pk_pow_b64=pk_pow_b64,
        original_filename=None,
    )

    wrapped_victim = wrap_file_key(victim["root_key"], file_key)
    enc_name_victim = encrypt_display_name(victim["root_key"], "victim-private-name.txt")

    r = client.post(
        "/files/upload/init",
        headers=victim["headers"],
        json={"tag_hex": tag_hex, "pk_pow_b64": pk_pow_b64, "manifest": manifest.to_dict()},
    )
    assert r.status_code == 200, r.text
    object_key = r.json()["upload_url"].split("https://fake-upload/", 1)[1]
    fake_minio.objects[object_key] = ciphertext

    r = client.post(
        "/files/upload/complete",
        headers=victim["headers"],
        json={
            "session_id": r.json()["session_id"],
            "tag_hex": tag_hex,
            "wrapped_kf_b64": wrapped_victim.ciphertext_b64,
            "wk_nonce_b64": wrapped_victim.nonce_b64,
            "manifest": manifest.to_dict(),
            "enc_display_name_b64": enc_name_victim.ciphertext_b64,
            "display_name_nonce_b64": enc_name_victim.nonce_b64,
        },
    )
    assert r.status_code == 200, r.text
    file_id = r.json()["file_id"]

    return {
        "victim": victim,
        "file_id": file_id,
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "manifest": manifest,
        "file_key": file_key,
        "signing_key": signing_key,
        "tag_hex": tag_hex,
    }


def test_plain_replay_of_victim_signature_is_rejected(app_client, tmp_path) -> None:
    """
    Current design should block naive replay.

    The victim signs a challenge issued for victim.user_id. The attacker then tries to submit
    that signature under attacker.user_id. ClaimService rebuilds the message with attacker.user_id
    and attacker's nonce, so verification must fail.
    """
    client = app_client.client
    lab = _upload_victim_file(app_client, tmp_path)
    attacker = _register_and_login(client, "relay-attacker-replay@example.com")

    # Victim challenge and victim signature.
    r = client.post("/files/challenge", headers=lab["victim"]["headers"], json={"tag_hex": lab["tag_hex"]})
    assert r.status_code == 200, r.text
    victim_challenge = r.json()
    victim_message = build_claim_message(
        context=victim_challenge["context"],
        user_id=str(lab["victim"]["user_id"]),
        tag_hex=lab["tag_hex"],
        nonce_b64=victim_challenge["nonce_b64"],
    )
    replayed_signature = sign_message_b64(lab["signing_key"], victim_message)

    # Attacker challenge exists, but attacker submits the victim-bound signature.
    r = client.post("/files/challenge", headers=attacker["headers"], json={"tag_hex": lab["tag_hex"]})
    assert r.status_code == 200, r.text

    fake_wrapped = wrap_file_key(attacker["root_key"], os.urandom(32))
    fake_name = encrypt_display_name(attacker["root_key"], "replay-should-fail.txt")
    r = client.post(
        "/files/claim",
        headers=attacker["headers"],
        json={
            "tag_hex": lab["tag_hex"],
            "wrapped_kf_b64": fake_wrapped.ciphertext_b64,
            "wk_nonce_b64": fake_wrapped.nonce_b64,
            "signature_b64": replayed_signature,
            "enc_display_name_b64": fake_name.ciphertext_b64,
            "display_name_nonce_b64": fake_name.nonce_b64,
        },
    )
    assert r.status_code == 401, r.text
    assert "Invalid proof" in r.text


def test_chosen_message_signature_relay_can_create_bogus_ownership(app_client, tmp_path) -> None:
    """
    Residual relay risk: if a victim-side signing oracle signs the attacker's exact challenge
    message, the server accepts the proof.

    Impact shown here is ownership/authorization confusion: attacker becomes an owner and can get
    download metadata/presigned URL. Because the attacker only relayed the signature and did not get
    the real file_key K, decryption still fails.
    """
    client = app_client.client
    lab = _upload_victim_file(app_client, tmp_path)
    attacker = _register_and_login(client, "relay-attacker-oracle@example.com")

    r = client.post("/files/challenge", headers=attacker["headers"], json={"tag_hex": lab["tag_hex"]})
    assert r.status_code == 200, r.text
    attacker_challenge = r.json()

    # This line simulates the vulnerable condition: victim's client signs a chosen message for
    # attacker.user_id + attacker.nonce. A normal client should not expose this signing oracle.
    attacker_bound_message = build_claim_message(
        context=attacker_challenge["context"],
        user_id=str(attacker["user_id"]),
        tag_hex=lab["tag_hex"],
        nonce_b64=attacker_challenge["nonce_b64"],
    )
    relayed_signature = sign_message_b64(lab["signing_key"], attacker_bound_message)

    # Attacker does NOT know file_key. They can still send any wrapped key because the API cannot
    # validate wrapped_kf_b64 server-side without breaking client-side encryption.
    fake_file_key = os.urandom(32)
    fake_wrapped = wrap_file_key(attacker["root_key"], fake_file_key)
    fake_name = encrypt_display_name(attacker["root_key"], "relay-bogus-owner.txt")

    r = client.post(
        "/files/claim",
        headers=attacker["headers"],
        json={
            "tag_hex": lab["tag_hex"],
            "wrapped_kf_b64": fake_wrapped.ciphertext_b64,
            "wk_nonce_b64": fake_wrapped.nonce_b64,
            "signature_b64": relayed_signature,
            "enc_display_name_b64": fake_name.ciphertext_b64,
            "display_name_nonce_b64": fake_name.nonce_b64,
        },
    )
    assert r.status_code == 200, r.text

    r = client.get("/files", headers=attacker["headers"])
    assert r.status_code == 200, r.text
    assert len(r.json()) == 1

    r = client.post("/files/download/init", headers=attacker["headers"], json={"file_id": lab["file_id"]})
    assert r.status_code == 200, r.text
    body = r.json()

    recovered_key = unwrap_file_key(attacker["root_key"], body["wrapped_kf_b64"], body["wk_nonce_b64"])
    assert recovered_key == fake_file_key

    with pytest.raises(Exception):
        decrypt_ciphertext(
            lab["ciphertext"],
            encryption_key=derive_encryption_key(recovered_key),
            manifest=Manifest.from_dict(body["manifest"]),
        )


def test_full_proof_bundle_relay_gives_real_access_if_file_key_is_also_relayed(app_client, tmp_path) -> None:
    """
    This is not a pure signature-relay anymore; it models a malicious helper that leaks both:
    1) a valid attacker-bound PoW signature, and
    2) the real file_key K, or an attacker-URK-wrapped copy of K.

    In that stronger compromised-client model, attacker can decrypt. This test documents the trust
    boundary: the client must protect both signing and key-wrapping operations.
    """
    client = app_client.client
    lab = _upload_victim_file(app_client, tmp_path)
    attacker = _register_and_login(client, "relay-attacker-full-bundle@example.com")

    r = client.post("/files/challenge", headers=attacker["headers"], json={"tag_hex": lab["tag_hex"]})
    assert r.status_code == 200, r.text
    ch = r.json()
    msg = build_claim_message(
        context=ch["context"],
        user_id=str(attacker["user_id"]),
        tag_hex=lab["tag_hex"],
        nonce_b64=ch["nonce_b64"],
    )
    sig = sign_message_b64(lab["signing_key"], msg)

    # Stronger compromise: the real file_key is now available to attacker-side wrapping.
    good_wrapped = wrap_file_key(attacker["root_key"], lab["file_key"])
    enc_name = encrypt_display_name(attacker["root_key"], "relay-full-access.txt")
    r = client.post(
        "/files/claim",
        headers=attacker["headers"],
        json={
            "tag_hex": lab["tag_hex"],
            "wrapped_kf_b64": good_wrapped.ciphertext_b64,
            "wk_nonce_b64": good_wrapped.nonce_b64,
            "signature_b64": sig,
            "enc_display_name_b64": enc_name.ciphertext_b64,
            "display_name_nonce_b64": enc_name.nonce_b64,
        },
    )
    assert r.status_code == 200, r.text

    r = client.post("/files/download/init", headers=attacker["headers"], json={"file_id": lab["file_id"]})
    assert r.status_code == 200, r.text
    body = r.json()
    recovered_key = unwrap_file_key(attacker["root_key"], body["wrapped_kf_b64"], body["wk_nonce_b64"])
    plaintext = decrypt_ciphertext(
        lab["ciphertext"],
        encryption_key=derive_encryption_key(recovered_key),
        manifest=Manifest.from_dict(body["manifest"]),
    )
    assert plaintext == lab["plaintext"]
