from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import re
import uuid
from collections.abc import Callable
from typing import Any

from evergarden.auth.credential_store import (
    CredentialNotFound,
    CredentialStore,
    CredentialStoreError,
)
from evergarden.mail.attachments import (
    MAX_DOWNLOAD_BYTES,
    AttachmentPolicyError,
    validate_download,
)

RECORD_PREFIX = "draft-attachment:"
MAX_ACTIVE_STAGED_ATTACHMENTS = 20
MAX_BASE64_CHARS = ((MAX_DOWNLOAD_BYTES + 2) // 3) * 4
STAGED_ATTACHMENT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class StagedAttachmentError(RuntimeError):
    pass


class StagedAttachmentStore:
    """Encrypted, immutable, expiring attachment staging for outbound drafts."""

    def __init__(
        self,
        store: CredentialStore,
        *,
        now: Callable[[], dt.datetime] | None = None,
        lifetime: dt.timedelta = dt.timedelta(hours=24),
    ):
        self.store = store
        self.now = now or (lambda: dt.datetime.now(dt.UTC))
        self.lifetime = lifetime

    @staticmethod
    def _record_id(staged_id: str) -> str:
        if not STAGED_ATTACHMENT_ID.fullmatch(str(staged_id)):
            raise StagedAttachmentError("staged attachment id is malformed")
        return f"{RECORD_PREFIX}{staged_id}"

    @staticmethod
    def _expiry(value: object) -> dt.datetime:
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise StagedAttachmentError("staged attachment expiry is malformed") from exc
        return parsed.replace(tzinfo=parsed.tzinfo or dt.UTC).astimezone(dt.UTC)

    def _active(self) -> list[tuple[str, dict[str, Any], int]]:
        current = self.now().astimezone(dt.UTC)
        active: list[tuple[str, dict[str, Any], int]] = []
        for item in self.store.metadata():
            record_id = str(item["record_id"])
            if not record_id.startswith(RECORD_PREFIX):
                continue
            try:
                value, version = self.store.get_with_version(record_id)
                expired = self._expiry(value.get("expires_at")) <= current
            except (CredentialStoreError, StagedAttachmentError):
                continue
            if value.get("consumed") or expired:
                if not value.get("consumed"):
                    self._tombstone(record_id, value, version, event="draft-attachment-expired")
                continue
            active.append((record_id, value, version))
        return active

    def stage(self, *, filename: str, mimetype: str, content_base64: str) -> dict[str, Any]:
        if not isinstance(content_base64, str) or len(content_base64) > MAX_BASE64_CHARS:
            raise StagedAttachmentError("attachment exceeds the 5 MiB staging limit")
        try:
            content = base64.b64decode(content_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise StagedAttachmentError("attachment content is not valid base64") from exc
        try:
            clean_name, media_type = validate_download(
                filename=filename,
                mimetype=mimetype,
                content=content,
                requested_max_bytes=MAX_DOWNLOAD_BYTES,
            )
        except AttachmentPolicyError as exc:
            raise StagedAttachmentError(str(exc)) from exc
        if len(self._active()) >= MAX_ACTIVE_STAGED_ATTACHMENTS:
            raise StagedAttachmentError("too many active staged attachments")
        staged_id = str(uuid.uuid4())
        now = self.now().astimezone(dt.UTC)
        value = {
            "schema_version": 1,
            "filename": clean_name,
            "mimetype": media_type,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_base64": content_base64,
            "created_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + self.lifetime).isoformat(timespec="seconds"),
            "consumed": False,
        }
        try:
            self.store.create_if_absent(
                self._record_id(staged_id),
                value=value,
                event="draft-attachment-staged",
            )
        except CredentialStoreError as exc:
            raise StagedAttachmentError("attachment could not be staged") from exc
        return {"staged_attachment_id": staged_id, **self._metadata(value)}

    @staticmethod
    def _metadata(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "filename": str(value["filename"]),
            "mimetype": str(value["mimetype"]),
            "size": int(value["size"]),
            "sha256": str(value["sha256"]),
            "expires_at": str(value["expires_at"]),
        }

    def describe(self, staged_id: str) -> dict[str, Any]:
        value = self._get_active(staged_id)[0]
        return {"staged_attachment_id": staged_id, **self._metadata(value)}

    def content(self, reference: dict[str, Any]) -> tuple[bytes, str, str]:
        staged_id = str(reference.get("staged_attachment_id") or "")
        value, _version = self._get_active(staged_id)
        metadata = self._metadata(value)
        for key in ("filename", "mimetype", "size", "sha256"):
            if reference.get(key) != metadata[key]:
                raise StagedAttachmentError("staged attachment changed after approval")
        try:
            content = base64.b64decode(str(value["content_base64"]), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise StagedAttachmentError("staged attachment content is malformed") from exc
        if hashlib.sha256(content).hexdigest() != metadata["sha256"]:
            raise StagedAttachmentError("staged attachment integrity check failed")
        return content, metadata["filename"], metadata["mimetype"]

    def _get_active(self, staged_id: str) -> tuple[dict[str, Any], int]:
        record_id = self._record_id(staged_id)
        try:
            value, version = self.store.get_with_version(record_id)
        except CredentialNotFound as exc:
            raise StagedAttachmentError("staged attachment was not found") from exc
        if (
            value.get("schema_version") != 1
            or value.get("consumed")
            or self._expiry(value.get("expires_at")) <= self.now().astimezone(dt.UTC)
        ):
            raise StagedAttachmentError("staged attachment is expired or consumed")
        return value, version

    def consume(self, references: list[dict[str, Any]]) -> None:
        for reference in references:
            staged_id = reference.get("staged_attachment_id")
            if not staged_id:
                continue
            record_id = self._record_id(str(staged_id))
            try:
                value, version = self._get_active(str(staged_id))
                self._tombstone(
                    record_id,
                    value,
                    version,
                    event="draft-attachment-consumed",
                )
            except StagedAttachmentError:
                continue

    def _tombstone(
        self, record_id: str, value: dict[str, Any], version: int, *, event: str
    ) -> None:
        tombstone = {
            "schema_version": 1,
            "filename": str(value.get("filename") or "attachment"),
            "mimetype": str(value.get("mimetype") or "application/octet-stream"),
            "size": int(value.get("size") or 0),
            "sha256": str(value.get("sha256") or ""),
            "created_at": str(value.get("created_at") or ""),
            "expires_at": str(value.get("expires_at") or ""),
            "consumed": True,
        }
        try:
            self.store.put_if_version(
                record_id,
                expected_version=version,
                value=tombstone,
                event=event,
            )
        except CredentialStoreError:
            return
