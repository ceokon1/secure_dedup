from __future__ import annotations

import argparse
import getpass
import os

from client_cli.api.http_client import APIClient
from client_cli.crypto.root_key import unlock_root_key_from_bootstrap
from client_cli.session.memory_session import MemorySession
from client_cli.session.token_store import TokenStore


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("login", help="Login and save a local session token")
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

    with APIClient(api_base_url) as api:
        login_response = api.login(email=args.email, password=password)
        access_token = str(login_response["access_token"])
        user_id = str(login_response["user_id"])
        api.set_token(access_token)

        # Optional but useful safety check: verify we can decrypt the encrypted root key.
        bootstrap = api.get_bootstrap()
        _ = unlock_root_key_from_bootstrap(password, bootstrap)

    session = MemorySession(
        access_token=access_token,
        user_id=user_id,
        email=args.email,
        api_base_url=api_base_url,
    )
    TokenStore(args.session_file).save(session)

    print("Login successful. Session saved locally.")
    print(f"session_file: {TokenStore(args.session_file).path}")
    return 0
