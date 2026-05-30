from __future__ import annotations

import base64
import hashlib
import hmac

from api.crypto.key_derivation_interface import KeyDeriver
from api.core.config import get_settings


class HMACKeyDeriver(KeyDeriver):
    """
    Development placeholder only.

    This is NOT a standard OPRF/VOPRF construction. It is provided so the rest of the
    codebase can keep a stable interface while you integrate a proper server-aided keying
    primitive later.
    """

    def __init__(self, secret: bytes) -> None:
        self.secret = secret

    def evaluate(self, input_hex: str) -> bytes:
        return hmac.new(self.secret, bytes.fromhex(input_hex), hashlib.sha256).digest()



def build_configured_deriver() -> KeyDeriver:
    settings = get_settings()
    secret = base64.b64decode(settings.oprf_secret_b64.encode("ascii"))
    return HMACKeyDeriver(secret)
