from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class MemorySession:
    access_token: str
    user_id: str
    email: str
    api_base_url: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemorySession":
        return cls(
            access_token=str(data["access_token"]),
            user_id=str(data["user_id"]),
            email=str(data["email"]),
            api_base_url=str(data["api_base_url"]),
        )

    @property
    def auth_header(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}
