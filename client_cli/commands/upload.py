from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from client_cli.api.http_client import APIClient
from client_cli.crypto.file_encrypt import encrypt_file
from client_cli.crypto.file_hash import sha256_file_hex
from client_cli.crypto.file_keys import derive_encryption_key, derive_file_key, derive_pow_seed
from client_cli.crypto.key_wrap import wrap_file_key
from client_cli.crypto.oprf_client import build_oprf_client
from client_cli.crypto.pow_sign import build_claim_message, derive_pow_material, sign_message_b64
from client_cli.crypto.private_metadata import encrypt_display_name
from client_cli.crypto.root_key import unlock_root_key_from_bootstrap
from client_cli.session.token_store import TokenStore


DEFAULT_CLAIM_CONTEXT = "pow-claim-v1"


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("upload", help="Encrypt, deduplicate, and upload a file")
    parser.add_argument("path", help="Path to the file to upload")
    parser.add_argument(
        "--password",
        default=None,
        help="Password used to unlock the encrypted user root key. If omitted, it is requested interactively.",
    )
    parser.add_argument(
        "--display-name",
        default=None,
        help="Optional local display name. It is encrypted per-user before being sent to the API. Defaults to the local file name.",
    )
    parser.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    input_path = Path(args.path)
    if not input_path.is_file():
        raise SystemExit(f"File not found: {input_path}")

    session = TokenStore(args.session_file).require()
    password = args.password or getpass.getpass("Password: ")

    with APIClient(session.api_base_url, token=session.access_token) as api:
        bootstrap = api.get_bootstrap()
        root_key = unlock_root_key_from_bootstrap(password, bootstrap)

        file_hash_hex, file_size = sha256_file_hex(input_path)
        oprf_client = build_oprf_client(session.api_base_url)
        oprf_output = oprf_client.evaluate(file_hash_hex=file_hash_hex)

        file_key = derive_file_key(oprf_output)
        encryption_key = derive_encryption_key(file_key)
        pow_seed = derive_pow_seed(file_key)
        signing_key, _public_key_bytes, pk_pow_b64, tag_hex = derive_pow_material(pow_seed)

        wrapped = wrap_file_key(root_key, file_key)
        display_name = args.display_name or input_path.name
        encrypted_display_name = encrypt_display_name(root_key, display_name)

        check = api.check_tag(tag_hex=tag_hex)
        exists = bool(check.get("exists", False))

        if exists:
            challenge = api.create_challenge(tag_hex=tag_hex)
            context = str(challenge.get("context", DEFAULT_CLAIM_CONTEXT))
            nonce_b64 = str(challenge["nonce_b64"])
            message = build_claim_message(
                context=context,
                user_id=session.user_id,
                tag_hex=tag_hex,
                nonce_b64=nonce_b64,
            )
            signature_b64 = sign_message_b64(signing_key, message)

            response = api.claim_existing(
                tag_hex=tag_hex,
                wrapped_kf_b64=wrapped.ciphertext_b64,
                wk_nonce_b64=wrapped.nonce_b64,
                signature_b64=signature_b64,
                enc_display_name_b64=encrypted_display_name.ciphertext_b64,
                display_name_nonce_b64=encrypted_display_name.nonce_b64,
            )
            print("Dedup hit: file already existed. Ownership claim stored without re-uploading ciphertext.")
            maybe_file_id = response.get("file_id") if isinstance(response, dict) else None
            if maybe_file_id:
                print(f"file_id: {maybe_file_id}")
            print(f"tag: {tag_hex}")
            print(f"file_size: {file_size} bytes")
            return 0

        ciphertext, manifest = encrypt_file(
            input_path,
            encryption_key=encryption_key,
            file_hash_hex=file_hash_hex,
            tag_hex=tag_hex,
            pk_pow_b64=pk_pow_b64,
            original_filename=None,
        )

        init = api.init_upload(
            tag_hex=tag_hex,
            pk_pow_b64=pk_pow_b64,
            manifest=manifest.to_dict(),
        )
        session_id = str(init["session_id"])
        upload_url = str(init["upload_url"])

        api.upload_presigned_bytes(
            upload_url=upload_url,
            payload=ciphertext,
            content_type=manifest.mime_type,
        )

        complete = api.complete_upload(
            session_id=session_id,
            tag_hex=tag_hex,
            wrapped_kf_b64=wrapped.ciphertext_b64,
            wk_nonce_b64=wrapped.nonce_b64,
            manifest=manifest.to_dict(),
            enc_display_name_b64=encrypted_display_name.ciphertext_b64,
            display_name_nonce_b64=encrypted_display_name.nonce_b64,
        )

    print("Upload successful.")
    maybe_file_id = complete.get("file_id") if isinstance(complete, dict) else None
    if maybe_file_id:
        print(f"file_id: {maybe_file_id}")
    print(f"tag: {tag_hex}")
    print(f"file_size: {file_size} bytes")
    print(f"ciphertext_size: {manifest.ciphertext_size} bytes")
    return 0
