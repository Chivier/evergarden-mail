from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any

MAX_STORED_ATTACHMENT_BYTES = 10 * 1024 * 1024

MAIL_PROVIDERS = frozenset({"gmail", "microsoft", "icloud", "imap"})
# Well-known provider IMAP endpoints used to auto-detect ``AccountConfig.provider``.
PROVIDER_IMAP_HOSTS: dict[str, frozenset[str]] = {
    "gmail": frozenset({"imap.gmail.com", "imap.googlemail.com"}),
    "microsoft": frozenset(
        {"outlook.office365.com", "outlook.office.com", "imap-mail.outlook.com"}
    ),
    "icloud": frozenset({"imap.mail.me.com"}),
}
_GMAIL_ROOTS = ("[gmail]/", "[google mail]/")
# Gmail system labels that are views, ranked so the broadest view sorts last.
_GMAIL_VIEW_RANKS = {"important": 1, "starred": 1, "all mail": 2}


def _is_gmail_system_folder(folder: str) -> bool:
    return folder.casefold().startswith(_GMAIL_ROOTS)


def _gmail_view_rank(folder: str) -> int | None:
    lowered = folder.casefold()
    for root in _GMAIL_ROOTS:
        if lowered.startswith(root):
            return _GMAIL_VIEW_RANKS.get(lowered.removeprefix(root))
    return None


@dataclasses.dataclass(frozen=True)
class AccountConfig:
    alias: str
    address: str
    imap_host: str
    imap_port: int = 993
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_mode: str = "starttls"
    auth_kind: str = "password"
    credential_record: str = ""
    folders: tuple[str, ...] = ("INBOX",)
    archive_folder: str = "Archive"
    sent_folder: str = "Sent"
    trash_folder: str = "Trash"
    safe_move_folders: tuple[str, ...] = ("Archive",)
    copy_preserve_source_fallback: bool = False
    send_from_addresses: tuple[str, ...] = ()
    enabled: bool = True
    # Optional provider family; empty means auto-detect from the IMAP host and
    # folder names (see ``mail_provider``).
    provider: str = ""

    @property
    def mail_provider(self) -> str:
        """Return the provider family that decides provider-specific folder traits."""
        if self.provider:
            return self.provider
        host = self.imap_host.casefold()
        for family, hosts in PROVIDER_IMAP_HOSTS.items():
            if host in hosts:
                return family
        if any(_is_gmail_system_folder(folder) for folder in self._all_folders):
            return "gmail"
        return "imap"

    @property
    def _all_folders(self) -> tuple[str, ...]:
        return (
            *self.folders,
            self.archive_folder,
            self.sent_folder,
            self.trash_folder,
            *self.safe_move_folders,
        )

    @property
    def label_view_folders(self) -> frozenset[str]:
        """Folders that are views over other mail rather than a place mail lives.

        Gmail exposes labels as IMAP folders; All Mail contains every message
        and Important/Starred are automatic labels, so none of them is an
        explicit organization destination.
        """
        if self.mail_provider != "gmail":
            return frozenset()
        return frozenset(
            folder for folder in self._all_folders if _gmail_view_rank(folder) is not None
        )

    @property
    def folder_precedence(self) -> tuple[str, ...]:
        """Configured folders in the order that decides a message's logical folder.

        The account's own ``folders`` order is authoritative, except that label
        views rank after every real folder (All Mail, the superset, last).
        """
        views = self.label_view_folders
        # sorted() is stable, so equal ranks keep their configured order.
        return tuple(
            sorted(
                self.folders,
                key=lambda folder: (_gmail_view_rank(folder) or 0) if folder in views else 0,
            )
        )

    @property
    def oauth_provider(self) -> str | None:
        if self.auth_kind != "oauth2":
            return None
        return "google" if self.imap_host.casefold() == "imap.gmail.com" else "microsoft"

    @property
    def allowed_from_addresses(self) -> tuple[str, ...]:
        """Return the explicit visible-From allowlist, with legacy configs pinned safely."""
        return self.send_from_addresses or (self.address,)

    @property
    def default_from_address(self) -> str:
        """Return the first allowlisted visible From identity."""
        return self.allowed_from_addresses[0]


@dataclasses.dataclass(frozen=True)
class AttachmentRecord:
    filename: str
    mimetype: str
    size: int
    content: bytes | None = dataclasses.field(default=None, repr=False, compare=False)


@dataclasses.dataclass(frozen=True)
class MessageRecord:
    stable_id: str
    account: str
    folder: str
    uid: int
    message_id: str
    sender_raw: str
    sender_name: str
    sender_email: str
    recipients_to: str
    recipients_cc: str
    subject: str
    date_received: str
    body_text: str
    body_html: str
    has_attachments: bool
    flags: tuple[str, ...]
    raw_size: int
    raw_body_sha256: str
    attachments: tuple[AttachmentRecord, ...] = ()
    in_reply_to: str = ""
    references_ids: tuple[str, ...] = ()
    reply_to: str = ""
    recipients_bcc: str = ""
    list_id: str = ""


def normalize_message_id(value: str | None) -> str:
    text = (value or "").strip().lower()
    return text[1:-1] if text.startswith("<") and text.endswith(">") else text


def stable_message_id(
    *,
    account: str,
    message_id: str | None,
    sender_email: str | None,
    date_received: str | None,
    subject: str | None,
    raw_size: int,
) -> str:
    normalized = normalize_message_id(message_id)
    parts: Iterable[str]
    if normalized:
        parts = (account.lower(), normalized)
    else:
        parts = (
            account.lower(),
            (sender_email or "").strip().lower(),
            (date_received or "").strip().lower(),
            (subject or "").strip().lower(),
            str(raw_size),
        )
    return hashlib.blake2b("\0".join(parts).encode(), digest_size=12).hexdigest()


class AccountConfigError(RuntimeError):
    """A private account inventory is missing, unsafe, or malformed."""


_ACCOUNT_KEYS = frozenset(field.name for field in dataclasses.fields(AccountConfig))
_REQUIRED_ACCOUNT_KEYS = frozenset(
    {
        "alias",
        "address",
        "imap_host",
        "smtp_host",
        "auth_kind",
        "credential_record",
        "folders",
        "archive_folder",
        "sent_folder",
        "trash_folder",
        "safe_move_folders",
    }
)
_TOKEN = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    re.I,
)
_ADDRESS = re.compile(r"[^@\s<>]+@[^@\s<>]+")
_FORBIDDEN_FOLDER = re.compile(
    r"(^|/)(trash|bin|deleted(?: items| messages)?|junk(?: e-mail| email)?|spam)(/|$)",
    re.I,
)


def _string(value: object, *, field: str, maximum: int = 255) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise AccountConfigError(f"account {field} is malformed")
    if any(character in value for character in "\r\n\0"):
        raise AccountConfigError(f"account {field} contains a control character")
    return value.strip()


def _folder_list(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise AccountConfigError(f"account {field} must contain 1-64 folders")
    folders = tuple(_string(item, field=field) for item in value)
    if len({item.casefold() for item in folders}) != len(folders):
        raise AccountConfigError(f"account {field} contains duplicate folders")
    return folders


def _address_list(value: object, *, field: str, primary: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise AccountConfigError(f"account {field} must contain 1-16 addresses")
    addresses = tuple(_string(item, field=field, maximum=320) for item in value)
    if any(not _ADDRESS.fullmatch(item) for item in addresses):
        raise AccountConfigError(f"account {field} contains a malformed address")
    normalized = [item.casefold() for item in addresses]
    if len(set(normalized)) != len(addresses):
        raise AccountConfigError(f"account {field} contains duplicate addresses")
    if primary.casefold() not in set(normalized):
        raise AccountConfigError(f"account {field} must include the authentication address")
    return addresses


def _port(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise AccountConfigError(f"account {field} must be a TCP port")
    return value


def _account_from_mapping(value: object) -> AccountConfig:
    if not isinstance(value, dict):
        raise AccountConfigError("each account entry must be an object")
    unexpected = sorted(set(value) - _ACCOUNT_KEYS)
    missing = sorted(_REQUIRED_ACCOUNT_KEYS - set(value))
    if unexpected:
        raise AccountConfigError(f"account entry has unexpected fields: {', '.join(unexpected)}")
    if missing:
        raise AccountConfigError(f"account entry is missing fields: {', '.join(missing)}")

    alias = _string(value["alias"], field="alias", maximum=64).casefold()
    if not _TOKEN.fullmatch(alias):
        raise AccountConfigError("account alias must be a lowercase token")
    address = _string(value["address"], field="address", maximum=320)
    if not _ADDRESS.fullmatch(address):
        raise AccountConfigError("account address is malformed")
    imap_host = _string(value["imap_host"], field="imap_host", maximum=253).casefold()
    smtp_host = _string(value["smtp_host"], field="smtp_host", maximum=253).casefold()
    if not _HOSTNAME.fullmatch(imap_host) or not _HOSTNAME.fullmatch(smtp_host):
        raise AccountConfigError("account provider host is malformed")
    auth_kind = _string(value["auth_kind"], field="auth_kind", maximum=16).casefold()
    if auth_kind not in {"oauth2", "password"}:
        raise AccountConfigError("account auth_kind must be oauth2 or password")
    if auth_kind == "oauth2" and imap_host == "imap.gmail.com" and smtp_host != "smtp.gmail.com":
        raise AccountConfigError("Google OAuth requires the Gmail IMAP and SMTP hosts")
    credential_record = _string(value["credential_record"], field="credential_record", maximum=200)
    if not re.fullmatch(r"[a-z0-9][a-z0-9:_-]{0,199}", credential_record, flags=re.I):
        raise AccountConfigError("account credential_record is malformed")
    folders = _folder_list(value["folders"], field="folders")
    safe_folders = _folder_list(value["safe_move_folders"], field="safe_move_folders")
    archive_folder = _string(value["archive_folder"], field="archive_folder")
    sent_folder = _string(value["sent_folder"], field="sent_folder")
    trash_folder = _string(value["trash_folder"], field="trash_folder")
    if archive_folder.casefold() not in {item.casefold() for item in safe_folders}:
        raise AccountConfigError("account archive_folder must be allowlisted for safe moves")
    if any(_FORBIDDEN_FOLDER.search(item) for item in safe_folders):
        raise AccountConfigError("destructive or junk folders cannot be safe move destinations")
    if trash_folder.casefold() in {
        archive_folder.casefold(),
        sent_folder.casefold(),
        *(item.casefold() for item in safe_folders),
    }:
        raise AccountConfigError("account trash_folder must be separate from safe destinations")
    fallback = value.get("copy_preserve_source_fallback", False)
    if not isinstance(fallback, bool):
        raise AccountConfigError("account copy_preserve_source_fallback must be boolean")
    enabled = value.get("enabled", True)
    if not isinstance(enabled, bool):
        raise AccountConfigError("account enabled must be boolean")
    smtp_mode = _string(value.get("smtp_mode", "starttls"), field="smtp_mode", maximum=16)
    if smtp_mode not in {"ssl", "starttls"}:
        raise AccountConfigError("account smtp_mode must be ssl or starttls")
    send_from_addresses = _address_list(
        value.get("send_from_addresses", [address]),
        field="send_from_addresses",
        primary=address,
    )
    provider = value.get("provider", "")
    if not isinstance(provider, str) or (provider and provider not in MAIL_PROVIDERS):
        raise AccountConfigError(
            f"account provider must be one of: {', '.join(sorted(MAIL_PROVIDERS))}"
        )
    return AccountConfig(
        alias=alias,
        address=address,
        imap_host=imap_host,
        imap_port=_port(value.get("imap_port", 993), field="imap_port"),
        smtp_host=smtp_host,
        smtp_port=_port(value.get("smtp_port", 587), field="smtp_port"),
        smtp_mode=smtp_mode,
        auth_kind=auth_kind,
        credential_record=credential_record,
        folders=folders,
        archive_folder=archive_folder,
        sent_folder=sent_folder,
        trash_folder=trash_folder,
        safe_move_folders=safe_folders,
        copy_preserve_source_fallback=fallback,
        send_from_addresses=send_from_addresses,
        enabled=enabled,
        provider=provider,
    )


def folder_precedence_by_alias(accounts: Iterable[AccountConfig]) -> dict[str, tuple[str, ...]]:
    """Map each account alias to its logical-folder precedence."""
    return {account.alias: account.folder_precedence for account in accounts}


def _account_payload(account: AccountConfig) -> dict[str, Any]:
    payload = {
        **dataclasses.asdict(account),
        "folders": list(account.folders),
        "safe_move_folders": list(account.safe_move_folders),
        "send_from_addresses": list(account.allowed_from_addresses),
    }
    if not account.provider:
        # Auto-detected; keep files written before the field existed unchanged.
        payload.pop("provider")
    return payload


def account_config_payload(accounts: Iterable[AccountConfig]) -> dict[str, Any]:
    """Return the non-secret account inventory shape used by private config files."""
    return {
        "schema_version": 1,
        "accounts": [_account_payload(account) for account in accounts],
    }


def parse_account_config_payload(
    value: object, *, include_disabled: bool = False
) -> tuple[AccountConfig, ...]:
    """Validate an account inventory already decoded from its private JSON file."""
    if not isinstance(value, dict) or set(value) != {"schema_version", "accounts"}:
        raise AccountConfigError("private account config root is malformed")
    if value["schema_version"] != 1:
        raise AccountConfigError("private account config schema version is unsupported")
    entries = value["accounts"]
    if not isinstance(entries, list) or not 0 <= len(entries) <= 16:
        raise AccountConfigError("private account config must contain 0-16 accounts")
    accounts = tuple(_account_from_mapping(item) for item in entries)
    aliases = [item.alias for item in accounts]
    addresses = [item.address.casefold() for item in accounts]
    send_from_addresses = [
        address.casefold() for account in accounts for address in account.allowed_from_addresses
    ]
    records = [item.credential_record.casefold() for item in accounts]
    if len(set(aliases)) != len(aliases):
        raise AccountConfigError("private account config contains duplicate aliases")
    if len(set(addresses)) != len(addresses):
        raise AccountConfigError("private account config contains duplicate addresses")
    if len(set(send_from_addresses)) != len(send_from_addresses):
        raise AccountConfigError("private account config contains duplicate send-from addresses")
    if len(set(records)) != len(records):
        raise AccountConfigError("private account config contains duplicate credential records")
    return (
        accounts if include_disabled else tuple(account for account in accounts if account.enabled)
    )


def load_account_configs(
    path: Path | None, *, include_disabled: bool = False
) -> tuple[AccountConfig, ...]:
    """Load private mailbox identities; no configured file means no accounts.

    There is deliberately no built-in inventory: set
    ``EVERGARDEN_ACCOUNT_CONFIG_FILE`` to a private account file. A configured
    file contains personal addresses, so it must be a regular, non-symlink file
    with no group/world permissions. Provider passwords and OAuth tokens are
    deliberately not part of this schema.
    """
    if path is None:
        return ()
    if path.is_symlink():
        raise AccountConfigError("account config must not be a symlink")
    try:
        info = path.stat()
    except FileNotFoundError as exc:
        raise AccountConfigError("private account config file is missing") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise AccountConfigError("private account config must be a regular mode-0600 file")
    if info.st_size > 128 * 1024:
        raise AccountConfigError("private account config exceeds 128 KiB")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AccountConfigError("private account config is not valid JSON") from exc
    return parse_account_config_payload(value, include_disabled=include_disabled)
