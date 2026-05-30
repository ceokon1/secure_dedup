from __future__ import annotations

import base64
import hashlib
import hmac
import os

from api.integrations.jwt_manager import create_access_token


PBKDF2_ITERATIONS = 200_000


def require_password_strength(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "$".join(
        [
            "pbkdf2_sha256",
            str(PBKDF2_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        ]
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algo, iterations_s, salt_b64, digest_b64 = password_hash.split("$", 3)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False

    salt = base64.b64decode(salt_b64.encode("ascii"))
    expected = base64.b64decode(digest_b64.encode("ascii"))
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        int(iterations_s),
    )
    return hmac.compare_digest(actual, expected)


__all__ = [
    "create_access_token",
    "hash_password",
    "require_password_strength",
    "verify_password",
]
