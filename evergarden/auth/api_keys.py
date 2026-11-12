from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
from pathlib import Path
from typing import Any

from evergarden.auth.policy import supported_scopes
from evergarden.private_json import PrivateJsonStore
from evergarden.private_json import revision as _revision

MAX_API_KEY_REGISTRY_BYTES = 64 * 1024
# Mirrors the reader-side ceiling in CompatibilityTokenVerifier so a registry
# this manager writes can never be one the MCP service refuses to load.
MAX_API_KEYS = 32
MAX_TTL_DAYS = 365
# Every client id issued here carries this prefix, so a self-service key can
# never collide with — or impersonate — a SOPS-provisioned infrastructure
# client such as "mail-ui" or "codex".
CLIENT_ID_PREFIX = "ui-"
MAX_LABEL_LENGTH = 48
TOKEN_BYTES = 48


class ApiKeyError(RuntimeError):
    pass


class ApiKeyConflict(ApiKeyError):
    pass


def _slug(label: str) -> str:
    slug = re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", label.strip().casefold())).strip("-")
    return slug[:32] or "key"


class ApiKeyManager:
    """Issue, list, and revoke self-service MCP bearer tokens.

    Only the SHA-256 of a token is ever written to disk; the plaintext exists in
    exactly one create() return value and is unrecoverable afterwards. The
    on-disk shape is the same registry format the MCP service already verifies,
    so no new parser sits on the authentication path.
    """

    def __init__(self, path: Path, *, resource: str, mode: str):
        self.path = path
        self.resource = resource
        self.mode = mode
        self.store = PrivateJsonStore(path, label="API key registry", error_type=ApiKeyError)

    def _read(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        value = self.store.read_json(max_bytes=MAX_API_KEY_REGISTRY_BYTES, default={"tokens": []})
        entries = value.get("tokens")
        if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
            raise ApiKeyError("API key registry is malformed")
        return value, list(entries)

    def _write(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        return self.store.write_json({"tokens": entries})

    @staticmethod
    def _check_revision(expected: str, value: dict[str, Any]) -> None:
        if not isinstance(expected, str) or expected != _revision(value):
            raise ApiKeyConflict("API key inventory changed; reload before editing")

    def _public(self, value: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
        now = dt.datetime.now(dt.UTC)
        return {
            "revision": _revision(value),
            "max_keys": MAX_API_KEYS,
            "keys": [
                {
                    "client_id": entry["client_id"],
                    "label": entry.get("label", entry["client_id"]),
                    "scopes": list(entry.get("scopes", [])),
                    "created_at": entry.get("created_at", ""),
                    "expires_at": entry["expires_at"],
                    "expired": dt.datetime.fromisoformat(
                        str(entry["expires_at"]).replace("Z", "+00:00")
                    ).astimezone(dt.UTC)
                    <= now,
                }
                for entry in entries
            ],
        }

    def snapshot(self) -> dict[str, Any]:
        with self.store.lock():
            value, entries = self._read()
            return self._public(value, entries)

    def _validate(self, label: object, scopes: object, ttl_days: object) -> tuple[str, list[str]]:
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= MAX_LABEL_LENGTH:
            raise ApiKeyError("API key name must be 1-48 characters")
        if not isinstance(ttl_days, int) or isinstance(ttl_days, bool):
            raise ApiKeyError("API key lifetime must be a whole number of days")
        if not 1 <= ttl_days <= MAX_TTL_DAYS:
            raise ApiKeyError(f"API key lifetime must be between 1 and {MAX_TTL_DAYS} days")
        known = set(supported_scopes())
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(scope, str) or scope not in known for scope in scopes)
        ):
            raise ApiKeyError("API key scopes must be a non-empty subset of the served scopes")
        return label.strip(), sorted(set(scopes))

    def create(
        self,
        *,
        label: object,
        scopes: object,
        ttl_days: object,
        expected_revision: str,
    ) -> dict[str, Any]:
        clean_label, clean_scopes = self._validate(label, scopes, ttl_days)
        with self.store.lock():
            value, entries = self._read()
            self._check_revision(expected_revision, value)
            if len(entries) >= MAX_API_KEYS:
                raise ApiKeyError(f"at most {MAX_API_KEYS} API keys may exist; revoke one first")
            taken = {str(entry.get("client_id") or "") for entry in entries}
            base = f"{CLIENT_ID_PREFIX}{_slug(clean_label)}"
            client_id = base
            suffix = 2
            while client_id in taken:
                client_id = f"{base}-{suffix}"
                suffix += 1
            token = secrets.token_urlsafe(TOKEN_BYTES)
            now = dt.datetime.now(dt.UTC)
            entries.append(
                {
                    "sha256": hashlib.sha256(token.encode()).hexdigest(),
                    "client_id": client_id,
                    "label": clean_label,
                    "subject": f"{self.mode}:{client_id}",
                    "audience": [self.resource],
                    "scopes": clean_scopes,
                    "created_at": now.isoformat(timespec="seconds"),
                    "expires_at": (now + dt.timedelta(days=int(ttl_days))).isoformat(
                        timespec="seconds"
                    ),
                }
            )
            stored = self._write(entries)
            # The only moment this plaintext is ever readable. It is not stored,
            # logged, or recoverable; a lost key must be revoked and reissued.
            return {"token": token, "client_id": client_id, **self._public(stored, entries)}

    def revoke(self, client_id: object, *, expected_revision: str) -> dict[str, Any]:
        if not isinstance(client_id, str) or not client_id:
            raise ApiKeyError("API key identifier is malformed")
        with self.store.lock():
            value, entries = self._read()
            self._check_revision(expected_revision, value)
            remaining = [entry for entry in entries if entry.get("client_id") != client_id]
            if len(remaining) == len(entries):
                raise ApiKeyError("API key is unknown")
            stored = self._write(remaining)
            return self._public(stored, remaining)
