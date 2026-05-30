from __future__ import annotations

from api.db.base import Base
from api.db.session import engine
from api.models.file import File
from api.models.pow_challenge import PowChallenge
from api.models.upload_session import UploadSession
from api.models.user import User
from api.models.user_file import UserFile



def init_db() -> None:
    Base.metadata.create_all(bind=engine)
