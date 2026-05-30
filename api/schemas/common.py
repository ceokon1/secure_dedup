from __future__ import annotations

from pydantic import BaseModel


class MessageResponse(BaseModel):
    message: str


class DeleteResponse(BaseModel):
    file_id: str
    removed_ownership: bool
    object_deleted: bool
    message: str
