from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from client_cli.api.http_client import APIClient
from client_cli.crypto.file_encrypt import decrypt_ciphertext
from client_cli.crypto.file_keys import derive_encryption_key
from client_cli.crypto.key_wrap import unwrap_file_key
from client_cli.crypto.private_metadata import decrypt_display_name
from client_cli.crypto.root_key import unlock_root_key_from_bootstrap
from client_cli.models.manifest import Manifest
from client_cli.session.token_store import TokenStore


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("download", help="Download and decrypt a file")
    parser.add_argument("file_id", help="Logical file id returned by the API")
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output path. Defaults to the user-specific encrypted display name if available.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password used to unlock the encrypted user root key. If omitted, it is requested interactively.",
    )
    parser.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    session = TokenStore(args.session_file).require()
    password = args.password or getpass.getpass("Password: ")

    with APIClient(session.api_base_url, token=session.access_token) as api:
        bootstrap = api.get_bootstrap()
        root_key = unlock_root_key_from_bootstrap(password, bootstrap)

        init = api.init_download(file_id=args.file_id)
        manifest = Manifest.from_dict(init["manifest"])

        file_key = unwrap_file_key(
            root_key,
            wrapped_kf_b64=init["wrapped_kf_b64"],
            wk_nonce_b64=init["wk_nonce_b64"],
        )
        encryption_key = derive_encryption_key(file_key)

        ciphertext = api.download_presigned_bytes(download_url=init["download_url"])
        plaintext = decrypt_ciphertext(
            ciphertext,
            encryption_key=encryption_key,
            manifest=manifest,
        )

        suggested_name = None
        enc_display_name_b64 = init.get("enc_display_name_b64")
        display_name_nonce_b64 = init.get("display_name_nonce_b64")
        if enc_display_name_b64 and display_name_nonce_b64:
            suggested_name = decrypt_display_name(root_key, enc_display_name_b64, display_name_nonce_b64)

    if args.output:
        output_path = Path(args.output)
    elif suggested_name:
        output_path = Path(suggested_name)
    elif manifest.original_filename:
        output_path = Path(manifest.original_filename)
    else:
        output_path = Path(f"{args.file_id}.bin")

    output_path.write_bytes(plaintext)
    print("Download and decryption successful.")
    print(f"saved_to: {output_path.resolve()}")
    print(f"size: {len(plaintext)} bytes")
    return 0
