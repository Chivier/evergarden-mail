from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from evergarden.mail.models import (
    AccountConfig,
    AccountConfigError,
    account_config_payload,
    parse_account_config_payload,
)
from evergarden.private_json import PrivateJsonStore
from evergarden.private_json import revision as _revision

MAX_ACCOUNT_CONFIG_BYTES = 128 * 1024


class AccountAdminError(RuntimeError):
    pass


class AccountConfigConflict(AccountAdminError):
    pass


class AccountConfigManager:
    """Atomically manage the private, token-free mailbox inventory.

    Disable preserves an entry; remove only removes its configuration.
    No credential record, archive, or provider message is deleted here.
    """

    def __init__(self, path: Path):
        self.path = path
        self.store = PrivateJsonStore(path, label="account config", error_type=AccountAdminError)
        self.lock_path = self.store.lock_path

    def _lock(self):
        return self.store.lock()

    def _read(self) -> tuple[dict[str, Any], tuple[AccountConfig, ...]]:
        value = self.store.read_json(
            max_bytes=MAX_ACCOUNT_CONFIG_BYTES,
            default={"schema_version": 1, "accounts": []},
        )
        try:
            accounts = parse_account_config_payload(value, include_disabled=True)
        except AccountConfigError as exc:
            raise AccountAdminError("account config is malformed") from exc
        return value, accounts

    def _write(self, accounts: tuple[AccountConfig, ...]) -> dict[str, Any]:
        return self.store.write_json(account_config_payload(accounts))

    @staticmethod
    def _public(value: dict[str, Any], accounts: tuple[AccountConfig, ...]) -> dict[str, Any]:
        return {
            "revision": _revision(value),
            "accounts": [
                {
                    **account_config_payload((account,))["accounts"][0],
                    "alias": account.alias,
                    "address": account.address,
                    "default_from": account.default_from_address,
                    "send_from_addresses": list(account.allowed_from_addresses),
                    "auth_kind": account.auth_kind,
                    "oauth_provider": account.oauth_provider,
                    "imap_host": account.imap_host,
                    "smtp_host": account.smtp_host,
                    "archive_folder": account.archive_folder,
                    "sent_folder": account.sent_folder,
                    "trash_folder": account.trash_folder,
                    "safe_move_folders": list(account.safe_move_folders),
                    "enabled": account.enabled,
                }
                for account in accounts
            ],
            "restart_required_after_change": True,
            "disable_semantics": "disable-only; credentials and archived mail are preserved",
            "removal_semantics": "configuration-only; credentials, archived mail and approvals are preserved",
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock():
            value, accounts = self._read()
            return self._public(value, accounts)

    @staticmethod
    def _check_revision(expected: str, value: dict[str, Any]) -> None:
        if not isinstance(expected, str) or expected != _revision(value):
            raise AccountConfigConflict("account inventory changed; reload before editing")

    def add(self, raw_account: object, *, expected_revision: str) -> dict[str, Any]:
        with self._lock():
            value, accounts = self._read()
            self._check_revision(expected_revision, value)
            candidate_value = {"schema_version": 1, "accounts": [raw_account]}
            try:
                candidate = parse_account_config_payload(candidate_value, include_disabled=True)[0]
                updated = (*accounts, candidate)
                parse_account_config_payload(account_config_payload(updated), include_disabled=True)
            except (AccountConfigError, IndexError) as exc:
                raise AccountAdminError(
                    "new account configuration is malformed or duplicated"
                ) from exc
            stored = self._write(updated)
            return self._public(stored, updated)

    def set_enabled(self, alias: str, *, enabled: bool, expected_revision: str) -> dict[str, Any]:
        if not isinstance(alias, str) or not isinstance(enabled, bool):
            raise AccountAdminError("account state request is malformed")
        with self._lock():
            value, accounts = self._read()
            self._check_revision(expected_revision, value)
            if alias not in {account.alias for account in accounts}:
                raise AccountAdminError("account is unknown")
            updated = tuple(
                dataclasses.replace(account, enabled=enabled) if account.alias == alias else account
                for account in accounts
            )
            stored = self._write(updated)
            return self._public(stored, updated)

    def update(self, alias: str, changes: object, *, expected_revision: str) -> dict[str, Any]:
        with self._lock():
            value, accounts = self._read()
            self._check_revision(expected_revision, value)
            if not isinstance(changes, dict) or changes.get("alias", alias) != alias:
                raise AccountAdminError("account alias cannot be changed")
            if alias not in {account.alias for account in accounts}:
                raise AccountAdminError("account is unknown")
            payload = account_config_payload(accounts)
            for account in payload["accounts"]:
                if account["alias"] == alias:
                    account.update(changes)
            try:
                updated = parse_account_config_payload(payload, include_disabled=True)
            except AccountConfigError as exc:
                raise AccountAdminError(
                    "updated account configuration is malformed or duplicated"
                ) from exc
            stored = self._write(updated)
            return self._public(stored, updated)

    def remove(self, alias: str, *, expected_revision: str, confirmation: str) -> dict[str, Any]:
        if not alias or confirmation != alias:
            raise AccountAdminError("confirm removal with the account alias")
        with self._lock():
            value, accounts = self._read()
            self._check_revision(expected_revision, value)
            updated = tuple(account for account in accounts if account.alias != alias)
            if len(updated) == len(accounts):
                raise AccountAdminError("account is unknown")
            stored = self._write(updated)
            return self._public(stored, updated)


def _read_stdin_account() -> object:
    try:
        return json.load(sys.stdin)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AccountAdminError("stdin does not contain one account JSON object") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage Evergarden's private mailbox inventory")
    parser.add_argument("--config", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list")
    add = subparsers.add_parser("add")
    add.add_argument("--expected-revision", required=True)
    state = subparsers.add_parser("set-enabled")
    state.add_argument("alias")
    state.add_argument("--expected-revision", required=True)
    state.add_argument("--enabled", choices=("true", "false"), required=True)
    args = parser.parse_args()
    manager = AccountConfigManager(args.config)
    if args.command == "list":
        result = manager.snapshot()
    elif args.command == "add":
        result = manager.add(_read_stdin_account(), expected_revision=args.expected_revision)
    else:
        result = manager.set_enabled(
            args.alias,
            enabled=args.enabled == "true",
            expected_revision=args.expected_revision,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
