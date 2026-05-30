from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.core.config import get_settings
from api.crypto.tags import validate_tag_matches_public_key
from api.models.user import User
from api.repositories.file_repo import FileRepository
from api.repositories.upload_session_repo import UploadSessionRepository
from api.repositories.user_file_repo import UserFileRepository
from api.schemas.upload import (
    ManifestSchema,
    UploadCompleteRequest,
    UploadCompleteResponse,
    UploadInitRequest,
    UploadInitResponse,
)
from api.services.storage_service import StorageService


class UploadService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()
        self.file_repo = FileRepository(db)
        self.user_file_repo = UserFileRepository(db)
        self.upload_session_repo = UploadSessionRepository(db)
        self.storage = StorageService()

    def _sanitize_manifest(self, manifest: ManifestSchema) -> dict[str, object]:
        data = manifest.model_dump()
        data["original_filename"] = None
        return data

    def _validate_manifest_for_upload(self, tag_hex: str, pk_pow_b64: str, manifest: ManifestSchema) -> None:
        if manifest.original_filename:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File names must not be embedded inside the shared manifest")
        if manifest.tag_hex != tag_hex:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest tag does not match request tag")
        if manifest.pk_pow_b64 != pk_pow_b64:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest public key does not match request public key")
        if not validate_tag_matches_public_key(tag_hex, pk_pow_b64):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tag_hex does not match pk_pow_b64")

    def init_upload(self, user: User, payload: UploadInitRequest) -> UploadInitResponse:
        self._validate_manifest_for_upload(payload.tag_hex, payload.pk_pow_b64, payload.manifest)

        existing = self.file_repo.get_by_tag(payload.tag_hex)
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="File already exists; use /files/claim instead")

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.settings.upload_session_ttl_seconds)
        object_key = self.storage.build_object_key(payload.tag_hex)
        upload_session = self.upload_session_repo.create(
            user_id=user.id,
            tag_hex=payload.tag_hex,
            pk_pow_b64=payload.pk_pow_b64,
            object_key=object_key,
            manifest_json=self._sanitize_manifest(payload.manifest),
            display_name=None,
            expires_at=expires_at,
        )
        self.db.commit()
        self.db.refresh(upload_session)
        return UploadInitResponse(
            session_id=upload_session.id,
            upload_url=self.storage.create_upload_url(object_key),
        )

    def complete_upload(self, user: User, payload: UploadCompleteRequest) -> UploadCompleteResponse:
        session_model = self.upload_session_repo.get_by_id_and_user(payload.session_id, user.id)
        if session_model is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload session not found")
        if session_model.status != "PENDING":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Upload session is not pending")
        expires_at = session_model.expires_at
        if getattr(expires_at, "tzinfo", None) is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Upload session has expired")
        if session_model.tag_hex != payload.tag_hex:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tag_hex does not match upload session")
        if session_model.manifest_json != self._sanitize_manifest(payload.manifest):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest changed between init and complete")

        self.storage.assert_object_exists(session_model.object_key)

        file = self.file_repo.get_by_tag(payload.tag_hex)
        if file is None:
            try:
                file = self.file_repo.create(
                    tag_hex=payload.tag_hex,
                    pk_pow_b64=session_model.pk_pow_b64,
                    object_key=session_model.object_key,
                    manifest_json=self._sanitize_manifest(payload.manifest),
                    display_name=None,
                )
                self.db.flush()
            except IntegrityError:
                self.db.rollback()
                file = self.file_repo.get_by_tag(payload.tag_hex)
                session_model = self.upload_session_repo.get_by_id_and_user(payload.session_id, user.id)
                if file is None or session_model is None:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Concurrent upload conflict; please retry")

        if file.object_key != session_model.object_key:
            self.storage.remove_object_if_exists(session_model.object_key)

        existing_relation = self.user_file_repo.get_by_user_and_file(user.id, file.id)
        if existing_relation is None:
            self.user_file_repo.create(
                user_id=user.id,
                file_id=file.id,
                wrapped_kf_b64=payload.wrapped_kf_b64,
                wk_nonce_b64=payload.wk_nonce_b64,
                enc_display_name_b64=payload.enc_display_name_b64,
                display_name_nonce_b64=payload.display_name_nonce_b64,
            )
        self.upload_session_repo.mark_completed(session_model)
        self.db.commit()
        return UploadCompleteResponse(file_id=file.id, message="Upload completed")
