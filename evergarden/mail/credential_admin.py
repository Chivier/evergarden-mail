from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path

from evergarden.auth.credential_store import CredentialStore
from evergarden.auth.google_oauth import (
    GOOGLE_APPLICATION_RECORD,
    GoogleApplication,
    GoogleConfigurationError,
)
from evergarden.config import Settings, get_settings
from evergarden.mail.models import load_account_configs

MAX_PASSWORD_BYTES = 16 * 1024


class ProviderCredentialError(RuntimeError):
    pass


def import_google_client(store: CredentialStore, path: Path, *, redirect_uri: str) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise ProviderCredentialError(
            "Google client file must be an existing private regular file"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 1 <= info.st_size <= 65536:
            raise ProviderCredentialError(
                "Google client file must be a mode-0600 file of at most 64 KiB"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(65537)
        if len(payload) > 65536:
            raise ProviderCredentialError("Google client file exceeds 64 KiB")
        try:
            app = GoogleApplication.parse(json.loads(payload))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProviderCredentialError("Google client file is malformed") from exc
        if redirect_uri not in app.redirect_uris:
            raise GoogleConfigurationError(
                "GOOGLE_OAUTH_REDIRECT_UNREGISTERED: the Google OAuth client does not list the current redirect URI"
            )
        return store.put(GOOGLE_APPLICATION_RECORD, app.private_payload())
    finally:
        os.close(descriptor)


def _read_password() -> str:
    if sys.stdin.isatty():
        value = getpass.getpass("App password: ")
    else:
        payload = sys.stdin.buffer.read(MAX_PASSWORD_BYTES + 1)
        if len(payload) > MAX_PASSWORD_BYTES:
            raise ProviderCredentialError("password input exceeds 16 KiB")
        try:
            value = payload.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as exc:
            raise ProviderCredentialError("password input must be UTF-8") from exc
    if not value or len(value) > MAX_PASSWORD_BYTES or any(char in value for char in "\r\n\0"):
        raise ProviderCredentialError("password input is malformed")
    return value


def _runtime(settings: Settings) -> tuple[dict, CredentialStore]:
    accounts = {
        account.alias: account
        for account in load_account_configs(settings.account_config_file, include_disabled=True)
    }
    store = CredentialStore.from_key_file(
        settings.credential_db,
        key_file=settings.credential_key_file,
        host_id=settings.host_id,
    )
    return accounts, store


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage provider credentials without placing secret values in arguments"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    password = subparsers.add_parser("set-password")
    password.add_argument("--account", required=True)
    google = subparsers.add_parser("set-google-client")
    google.add_argument("--client-file", required=True, type=Path)
    args = parser.parse_args()
    settings = get_settings()
    accounts, store = _runtime(settings)
    if args.command == "status":
        existing = {item["record_id"]: item for item in store.metadata()}
        result = {
            "google_application_present": GOOGLE_APPLICATION_RECORD in existing,
            "accounts": [
                {
                    "account": account.alias,
                    "auth_kind": account.auth_kind,
                    "oauth_provider": account.oauth_provider,
                    "enabled": account.enabled,
                    "credential_present": account.credential_record in existing,
                    "credential_version": (
                        existing[account.credential_record]["version"]
                        if account.credential_record in existing
                        else None
                    ),
                }
                for account in accounts.values()
            ],
        }
    elif args.command == "set-google-client":
        try:
            revision = import_google_client(
                store, args.client_file, redirect_uri=settings.google_oauth_redirect_uri
            )
        except (ProviderCredentialError, GoogleConfigurationError) as exc:
            raise SystemExit(str(exc)) from exc
        result = {"provider": "google", "credential_version": revision, "stored": True}
    else:
        account = accounts.get(args.account)
        if account is None:
            raise SystemExit("unknown account alias")
        if account.auth_kind != "password":
            raise SystemExit("set-password is available only for app-password accounts")
        revision = store.put(
            account.credential_record,
            {"password": _read_password(), "provider": account.imap_host},
        )
        result = {"account": account.alias, "credential_version": revision, "stored": True}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
