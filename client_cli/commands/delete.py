from __future__ import annotations

import argparse

from client_cli.api.http_client import APIClient
from client_cli.session.token_store import TokenStore


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("delete", help="Delete a logical file ownership record")
    parser.add_argument("file_id", help="Logical file id to delete")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt",
    )
    parser.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    if not args.yes:
        answer = input(f"Delete file_id={args.file_id}? [y/N]: ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Cancelled.")
            return 0

    session = TokenStore(args.session_file).require()
    with APIClient(session.api_base_url, token=session.access_token) as api:
        response = api.delete_file(file_id=args.file_id)

    print("Delete request completed.")
    if isinstance(response, dict) and response:
        for key, value in response.items():
            print(f"{key}: {value}")
    return 0
