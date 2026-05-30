from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod

import httpx

from client_cli.crypto.password_kdf import b64d


class BaseOPRFClient(ABC):
    @abstractmethod
    def evaluate(self, *, file_hash_hex: str) -> bytes:
        raise NotImplementedError


class MockOPRFClient(BaseOPRFClient):
    """
    Development-only OPRF replacement.

    This is useful before the server-side OPRF/VOPRF is implemented.
    It is deterministic so dedup still works during development.
    """

    def evaluate(self, *, file_hash_hex: str) -> bytes:
        file_hash = bytes.fromhex(file_hash_hex)
        return hashlib.sha256(b"mock-oprf-evaluate|v1|" + file_hash).digest()


class HTTPOPRFClient(BaseOPRFClient):
    """
    Simple HTTP contract for the future server-side OPRF module.

    Expected endpoint:
      POST /oprf/evaluate
      request:  {"input_hex": "<sha256 of file>"}
      response: {"output_b64": "<opaque bytes>"}

    Replace this with a standard OPRF/VOPRF flow when the backend is ready.
    """

    def __init__(self, base_url: str, timeout_seconds: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def evaluate(self, *, file_hash_hex: str) -> bytes:
        response = httpx.post(
            f"{self.base_url}/oprf/evaluate",
            json={"input_hex": file_hash_hex},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        return b64d(data["output_b64"])


def build_oprf_client(base_url: str) -> BaseOPRFClient:
    mode = os.getenv("SECURE_DEDUP_OPRF_MODE", "mock").strip().lower()
    if mode == "http":
        return HTTPOPRFClient(base_url=base_url)
    return MockOPRFClient()
