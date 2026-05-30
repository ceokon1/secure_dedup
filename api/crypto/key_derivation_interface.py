from __future__ import annotations

from abc import ABC, abstractmethod


class KeyDeriver(ABC):
    @abstractmethod
    def evaluate(self, input_hex: str) -> bytes:
        raise NotImplementedError
