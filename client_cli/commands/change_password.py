from __future__ import annotations

import argparse
import getpass

from client_cli.api.http_client import APIClient
from client_cli.crypto.password_kdf import b64e, derive_kek, generate_salt
from client_cli.crypto.root_key import encrypt_root_key, unlock_root_key_from_bootstrap
from client_cli.session.token_store import TokenStore


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("change-password", help="Re-wrap the encrypted user root key with a new password")
    parser.add_argument(
        "--current-password",
        default=None,
        help="Current password. If omitted, it is requested interactively.",
    )
    parser.add_argument(
        "--new-password",
        default=None,
        help="New password. If omitted, it is requested interactively.",
    )
    parser.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    session = TokenStore(args.session_file).require()
    current_password = args.current_password or getpass.getpass("Current password: ")
    new_password = args.new_password or getpass.getpass("New password: ")
    confirm_password = getpass.getpass("Confirm new password: ")
    if new_password != confirm_password:
        raise SystemExit("New passwords do not match")
    if current_password == new_password:
        raise SystemExit("New password must be different from the current password")

    with APIClient(session.api_base_url, token=session.access_token) as api:
        bootstrap = api.get_bootstrap()
        root_key = unlock_root_key_from_bootstrap(current_password, bootstrap)

        kek_salt = generate_salt()
        kek = derive_kek(new_password, kek_salt)
        enc_root_key = encrypt_root_key(root_key, kek)

        api.change_password(
            current_password=current_password,
            new_password=new_password,
            enc_urk_b64=enc_root_key.ciphertext_b64,
            enc_urk_nonce_b64=enc_root_key.nonce_b64,
            kek_salt_b64=b64e(kek_salt),
        )

    print("Password changed successfully.")
    print("Your saved session token is still valid, but future logins now require the new password.")
    return 0
