from __future__ import annotations

import argparse
import getpass
import os

from client_cli.api.http_client import APIClient
from client_cli.crypto.password_kdf import b64e, derive_kek, generate_salt
from client_cli.crypto.root_key import encrypt_root_key, generate_root_key


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("register", help="Register a new user")
    parser.add_argument("email", help="User email")
    parser.add_argument(
        "--password",
        default=None,
        help="Password. If omitted, it is requested interactively.",
    )
    parser.set_defaults(handler=handle)


def _resolve_api_base_url(value: str | None) -> str:
    return value or os.getenv("SECURE_DEDUP_API_BASE_URL", "http://localhost:8000")


def handle(args: argparse.Namespace) -> int:
    api_base_url = _resolve_api_base_url(args.api_base_url)
    password = args.password or getpass.getpass("Password: ")
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        raise SystemExit("Passwords do not match")

    root_key = generate_root_key()
    kek_salt = generate_salt()
    kek = derive_kek(password, kek_salt)
    enc_root_key = encrypt_root_key(root_key, kek)

    with APIClient(api_base_url) as api:
        response = api.register(
            email=args.email,
            password=password,
            enc_urk_b64=enc_root_key.ciphertext_b64,
            enc_urk_nonce_b64=enc_root_key.nonce_b64,
            kek_salt_b64=b64e(kek_salt),
        )

    print("Registration successful.")
    if isinstance(response, dict):
        maybe_user_id = response.get("user_id")
        if maybe_user_id:
            print(f"user_id: {maybe_user_id}")
    print("Run the login command next.")
    return 0
