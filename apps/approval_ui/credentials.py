"""Administrator-only credential writes; plaintext is never read back."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr

from evergarden.auth.credential_store import CredentialStore, CredentialStoreError
from evergarden.config import Settings
from evergarden.mail.account_admin import (
    AccountAdminError,
    AccountConfigConflict,
    AccountConfigManager,
)
from evergarden.mail.models import AccountConfigError, load_account_configs


class PasswordRequest(BaseModel):
    expected_revision: str = Field(min_length=64, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=16384)


def install_credential_routes(
    app: FastAPI, settings: Settings, require_admin, require_csrf
) -> None:
    def store() -> CredentialStore:
        if not settings.mail_ui_account_admin_enabled or settings.account_config_file is None:
            raise HTTPException(status_code=503, detail="credential administration is fenced off")
        return CredentialStore.from_key_file(
            settings.credential_db,
            key_file=settings.credential_key_file,
            host_id=settings.host_id,
        )

    @app.get("/oauth/credentials")
    def credential_status(request: Request):
        require_admin(request)
        try:
            credentials = store()
            records = {item["record_id"] for item in credentials.metadata()}
            accounts = load_account_configs(settings.account_config_file, include_disabled=True)
            return {
                "accounts": [
                    {"alias": a.alias, "credential_present": a.credential_record in records}
                    for a in accounts
                ]
            }
        except (CredentialStoreError, AccountConfigError) as exc:
            raise HTTPException(
                status_code=503, detail="credential storage is unavailable"
            ) from exc

    @app.post("/oauth/credentials/{alias}/password")
    def set_password(alias: str, body: PasswordRequest, request: Request):
        current = require_admin(request)
        require_csrf(request, current)
        password = body.password.get_secret_value()
        if any(c in password for c in "\r\n\0") or len(password.encode()) > 16384:
            raise HTTPException(status_code=400, detail="app password is malformed")
        try:
            credentials = store()
            manager = AccountConfigManager(settings.account_config_file)
            # Use the same account lock as edits/removals so the password cannot
            # race an identity or credential-record change in another tab.
            with manager.store.read_lock():
                value, accounts = manager._read()
                manager._check_revision(body.expected_revision, value)
                account = next((a for a in accounts if a.alias == alias), None)
                if account is None or account.auth_kind != "password":
                    raise HTTPException(status_code=400, detail="select an app-password mailbox")
                version = credentials.put(
                    account.credential_record, {"password": password, "provider": account.imap_host}
                )
            return {"account": alias, "stored": True, "credential_version": version}
        except AccountConfigConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (CredentialStoreError, AccountConfigError, AccountAdminError) as exc:
            raise HTTPException(
                status_code=503, detail="credential storage is unavailable"
            ) from exc
