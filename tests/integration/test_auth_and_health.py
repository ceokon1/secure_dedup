from __future__ import annotations

from client_cli.crypto.password_kdf import b64e, derive_kek, generate_salt
from client_cli.crypto.root_key import decrypt_root_key, encrypt_root_key, generate_root_key


def test_health_endpoint(app_client) -> None:
    response = app_client.client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


def test_register_login_bootstrap(app_client) -> None:
    register_payload = {
        "email": "alice@example.com",
        "password": "password123",
        "enc_urk_b64": "dGVzdA==",
        "enc_urk_nonce_b64": "dGVzdA==",
        "kek_salt_b64": "dGVzdA==",
    }
    response = app_client.client.post("/auth/register", json=register_payload)
    assert response.status_code == 200
    user_id = response.json()["user_id"]

    response = app_client.client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "password123"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    response = app_client.client.get(
        "/auth/me/bootstrap",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    bootstrap = response.json()
    assert bootstrap["user_id"] == user_id
    assert bootstrap["email"] == "alice@example.com"


def test_change_password_rewraps_same_root_key(app_client) -> None:
    root_key = generate_root_key()
    old_salt = generate_salt()
    old_kek = derive_kek("password123", old_salt)
    enc_old = encrypt_root_key(root_key, old_kek)

    register_payload = {
        "email": "charlie@example.com",
        "password": "password123",
        "enc_urk_b64": enc_old.ciphertext_b64,
        "enc_urk_nonce_b64": enc_old.nonce_b64,
        "kek_salt_b64": b64e(old_salt),
    }
    response = app_client.client.post("/auth/register", json=register_payload)
    assert response.status_code == 200

    response = app_client.client.post(
        "/auth/login",
        json={"email": "charlie@example.com", "password": "password123"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    new_salt = generate_salt()
    new_kek = derive_kek("new-password-123", new_salt)
    enc_new = encrypt_root_key(root_key, new_kek)

    response = app_client.client.post(
        "/auth/change-password",
        json={
            "current_password": "password123",
            "new_password": "new-password-123",
            "enc_urk_b64": enc_new.ciphertext_b64,
            "enc_urk_nonce_b64": enc_new.nonce_b64,
            "kek_salt_b64": b64e(new_salt),
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    response = app_client.client.post(
        "/auth/login",
        json={"email": "charlie@example.com", "password": "password123"},
    )
    assert response.status_code == 401

    response = app_client.client.post(
        "/auth/login",
        json={"email": "charlie@example.com", "password": "new-password-123"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    response = app_client.client.get(
        "/auth/me/bootstrap",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    bootstrap = response.json()
    recovered = decrypt_root_key(bootstrap["enc_urk_b64"], bootstrap["enc_urk_nonce_b64"], new_kek)
    assert recovered == root_key
