from __future__ import annotations

import argparse
from typing import Optional, Sequence

from client_cli.commands import change_password, delete, download, list_files, login, register, upload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-dedup-cli",
        description="Python CLI for a secure deduplicated storage demo.",
    )
    parser.add_argument(
        "--api-base-url",
        dest="api_base_url",
        default=None,
        help="FastAPI base URL. Defaults to SECURE_DEDUP_API_BASE_URL or the URL saved in the session store.",
    )
    parser.add_argument(
        "--session-file",
        dest="session_file",
        default=None,
        help="Path to the local session file. Defaults to ~/.secure_dedup_cli/session.json",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    register.add_parser(subparsers)
    login.add_parser(subparsers)
    change_password.add_parser(subparsers)
    upload.add_parser(subparsers)
    download.add_parser(subparsers)
    list_files.add_parser(subparsers)
    delete.add_parser(subparsers)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
