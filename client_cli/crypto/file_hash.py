from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_bytes_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file_hex(path: str | Path, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    hasher = hashlib.sha256()
    total_size = 0
    file_path = Path(path)

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            total_size += len(chunk)

    return hasher.hexdigest(), total_size
