from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from client_cli.session.memory_session import MemorySession


DEFAULT_SESSION_PATH = Path.home() / ".secure_dedup_cli" / "session.json"


class TokenStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_SESSION_PATH

    def save(self, session: MemorySession) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(session.to_dict(), f, indent=2)
        try:
            os.chmod(self.path, 0o600)
        except PermissionError:
            # Windows may reject chmod like this; ignore quietly.
            pass

    def load(self) -> Optional[MemorySession]:
        if not self.path.exists():
            return None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return MemorySession.from_dict(data)

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def require(self) -> MemorySession:
        session = self.load()
        if session is None:
            raise RuntimeError(
                f"No saved session found at {self.path}. Run the login command first."
            )
        return session
