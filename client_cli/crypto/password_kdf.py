from __future__ import annotations

import base64
import os

from argon2.low_level import Type, hash_secret_raw

# Reasonable demo defaults. Tune on the target machine if needed.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
DEFAULT_SALT_BYTES = 16


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


def generate_salt(num_bytes: int = DEFAULT_SALT_BYTES) -> bytes:
    return os.urandom(num_bytes)


def derive_kek(
    password: str,
    salt: bytes,
    *,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost_kib: int = ARGON2_MEMORY_COST_KIB,
    parallelism: int = ARGON2_PARALLELISM,
    hash_len: int = ARGON2_HASH_LEN,
) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )
