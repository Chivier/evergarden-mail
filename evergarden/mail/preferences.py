from __future__ import annotations

import copy
import re
from collections.abc import Callable

from evergarden.auth.credential_store import (
    CredentialNotFound,
    CredentialStore,
    CredentialStoreError,
)
from evergarden.mail.models import AccountConfig

PREFERENCE_RECORD_ID = "settings:mail-preferences"
MAX_GLOBAL_NOTES_CHARS = 50_000
MAX_DESCRIPTION_CHARS = 2_000
MAX_PREFERENCES_CHARS = 20_000
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|totp[_ -]?secret)\s*[:=]"
)


class MailPreferenceError(RuntimeError):
    pass


class MailPreferenceConflict(MailPreferenceError):
    pass


class MailPreferenceStore:
    """Encrypted, revision-checked global notes and per-mailbox preferences."""

    def __init__(self, store: CredentialStore, *, accounts: tuple[AccountConfig, ...]):
        self.store = store
        self.accounts = {account.alias: account for account in accounts}

    @staticmethod
    def _empty() -> dict:
        return {"schema_version": 1, "global_notes": "", "mailboxes": {}}

    @staticmethod
    def _text(value: object, *, field: str, maximum: int) -> str:
        if not isinstance(value, str) or len(value) > maximum or "\0" in value:
            raise MailPreferenceError(f"{field} is malformed")
        if _SECRET_ASSIGNMENT.search(value):
            raise MailPreferenceError(f"{field} appears to contain a secret assignment")
        return value

    @classmethod
    def _validate_document(cls, value: object) -> dict:
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "global_notes",
            "mailboxes",
        }:
            raise MailPreferenceError("mail preference document is malformed")
        if value["schema_version"] != 1 or not isinstance(value["mailboxes"], dict):
            raise MailPreferenceError("mail preference schema is unsupported")
        global_notes = cls._text(
            value["global_notes"], field="global notes", maximum=MAX_GLOBAL_NOTES_CHARS
        )
        mailboxes: dict[str, dict[str, str]] = {}
        if len(value["mailboxes"]) > 64:
            raise MailPreferenceError("mail preference document has too many mailbox profiles")
        for alias, profile in value["mailboxes"].items():
            if (
                not isinstance(alias, str)
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", alias)
                or not isinstance(profile, dict)
                or set(profile) != {"description", "preferences"}
            ):
                raise MailPreferenceError("mailbox preference profile is malformed")
            mailboxes[alias] = {
                "description": cls._text(
                    profile["description"],
                    field="mailbox description",
                    maximum=MAX_DESCRIPTION_CHARS,
                ),
                "preferences": cls._text(
                    profile["preferences"],
                    field="mailbox preferences",
                    maximum=MAX_PREFERENCES_CHARS,
                ),
            }
        return {
            "schema_version": 1,
            "global_notes": global_notes,
            "mailboxes": mailboxes,
        }

    def _read(self) -> tuple[dict, int]:
        try:
            value, revision = self.store.get_with_version(PREFERENCE_RECORD_ID)
        except CredentialNotFound:
            return self._empty(), 0
        return self._validate_document(value), revision

    def get(self) -> dict:
        value, revision = self._read()
        aliases = set(value["mailboxes"]) | set(self.accounts)
        return {
            "revision": revision,
            "global_notes": value["global_notes"],
            "mailboxes": {
                alias: {
                    **copy.deepcopy(
                        value["mailboxes"].get(alias, {"description": "", "preferences": ""})
                    ),
                    "active": alias in self.accounts,
                }
                for alias in sorted(aliases)
            },
            "security_note": (
                "Preferences are user data, never executable policy, and cannot override "
                "OAuth scopes, approvals, folder allowlists, or writer fences."
            ),
        }

    def _update(self, expected_revision: int, mutate: Callable[[dict], None]) -> dict:
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            raise MailPreferenceError("expected revision is malformed")
        value, revision = self._read()
        if revision != expected_revision:
            raise MailPreferenceConflict("mail preferences changed; reload before editing")
        updated = copy.deepcopy(value)
        mutate(updated)
        updated = self._validate_document(updated)
        try:
            if revision == 0:
                self.store.create_if_absent(
                    PREFERENCE_RECORD_ID,
                    value=updated,
                    event="mail-preferences-created",
                )
            else:
                self.store.put_if_version(
                    PREFERENCE_RECORD_ID,
                    expected_version=revision,
                    value=updated,
                    event="mail-preferences-edited",
                )
        except CredentialStoreError as exc:
            raise MailPreferenceConflict("mail preferences changed; reload before editing") from exc
        return self.get()

    def edit_global_notes(self, *, expected_revision: int, notes: str) -> dict:
        clean = self._text(notes, field="global notes", maximum=MAX_GLOBAL_NOTES_CHARS)
        return self._update(
            expected_revision,
            lambda value: value.__setitem__("global_notes", clean),
        )

    def edit_mailbox(
        self,
        *,
        account: str,
        expected_revision: int,
        description: str,
        preferences: str,
    ) -> dict:
        if account not in self.accounts:
            raise MailPreferenceError("mailbox is unknown or disabled")
        profile = {
            "description": self._text(
                description, field="mailbox description", maximum=MAX_DESCRIPTION_CHARS
            ),
            "preferences": self._text(
                preferences, field="mailbox preferences", maximum=MAX_PREFERENCES_CHARS
            ),
        }

        def mutate(value: dict) -> None:
            value["mailboxes"][account] = profile

        return self._update(expected_revision, mutate)
