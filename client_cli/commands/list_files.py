from __future__ import annotations

import argparse
import getpass

from client_cli.api.http_client import APIClient
from client_cli.crypto.private_metadata import decrypt_display_name
from client_cli.crypto.root_key import unlock_root_key_from_bootstrap
from client_cli.session.token_store import TokenStore


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("list-files", help="List files owned by the current user")
    parser.add_argument(
        "--password",
        default=None,
        help="Password used to unlock and decrypt private file names. If omitted, it is requested interactively.",
    )
    parser.set_defaults(handler=handle)


def _truncate(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def handle(args: argparse.Namespace) -> int:
    session = TokenStore(args.session_file).require()
    password = args.password or getpass.getpass("Password: ")

    with APIClient(session.api_base_url, token=session.access_token) as api:
        bootstrap = api.get_bootstrap()
        root_key = unlock_root_key_from_bootstrap(password, bootstrap)
        items = api.list_files()

    if not items:
        print("No files found.")
        return 0

    headers = ["file_id", "display_name", "tag", "created_at"]
    widths = {h: len(h) for h in headers}

    rows = []
    for item in items:
        display_name = ""
        enc_display_name_b64 = item.get("enc_display_name_b64")
        display_name_nonce_b64 = item.get("display_name_nonce_b64")
        if enc_display_name_b64 and display_name_nonce_b64:
            display_name = decrypt_display_name(root_key, enc_display_name_b64, display_name_nonce_b64)
        else:
            display_name = str(item.get("display_name") or item.get("original_filename") or "")

        row = {
            "file_id": str(item.get("file_id") or item.get("id") or ""),
            "display_name": display_name,
            "tag": str(item.get("tag_hex") or item.get("tag") or ""),
            "created_at": str(item.get("created_at") or ""),
        }
        row["display_name"] = _truncate(row["display_name"], 40)
        row["tag"] = _truncate(row["tag"], 24)
        rows.append(row)
        for key, value in row.items():
            widths[key] = max(widths[key], len(value))

    fmt = "  ".join(f"{{:{widths[h]}}}" for h in headers)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * widths[h] for h in headers]))
    for row in rows:
        print(fmt.format(row["file_id"], row["display_name"], row["tag"], row["created_at"]))
    return 0
