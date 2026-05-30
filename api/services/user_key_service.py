from __future__ import annotations

from api.models.user import User
from api.schemas.auth import BootstrapResponse


class UserKeyService:
    def bootstrap_payload(self, user: User) -> BootstrapResponse:
        return BootstrapResponse(
            user_id=user.id,
            email=user.email,
            enc_urk_b64=user.enc_urk_b64,
            enc_urk_nonce_b64=user.enc_urk_nonce_b64,
            kek_salt_b64=user.kek_salt_b64,
        )
