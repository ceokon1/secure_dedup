from __future__ import annotations

import hashlib

from api.crypto.key_derivation_interface import KeyDeriver


class MockKeyDeriver(KeyDeriver):
    """
    Development-only deterministic file-key precursor.
    Replace with a standard OPRF/VOPRF deployment later.
    """

    def evaluate(self, input_hex: str) -> bytes:
        return hashlib.sha256(b"mock-oprf-evaluate|v1|" + bytes.fromhex(input_hex)).digest()
