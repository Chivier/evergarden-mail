from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import email.policy
import hashlib
import imaplib
import logging
import re
import smtplib
import ssl
import threading
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import format_datetime
from typing import Any, Protocol

from evergarden.approvals.service import (
    ProviderDefinitelyRejected,
    ProviderNotAttempted,
    ProviderOutcomeUnknown,
    ProviderPartialOutcome,
    ProviderProvedNotApplied,
    ProviderSourceGone,
)
from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter
from evergarden.audit.redaction import redact_text
from evergarden.auth.credential_store import CredentialStore
from evergarden.mail.imap_connector import ImapConnector, UnsupportedAuthKind
from evergarden.mail.models import AccountConfig, normalize_message_id
from evergarden.mail.smtp_connector import SmtpConnector, UnsupportedSmtpMode
from evergarden.mail.staged_attachments import StagedAttachmentError, StagedAttachmentStore
from evergarden.mail.sync import (
    MailboxSyncBusy,
    _parse_fetch_flags,
    _quote_folder,
    account_sync_lock,
    parse_message,
)

LOGGER = logging.getLogger(__name__)


def _message_id_anchored(payload: dict) -> bool:
    """Whether the payload carries identity strong enough to survive a byte rewrite."""
    return bool(
        normalize_message_id(str(payload.get("provider_message_id") or ""))
        and payload.get("stable_message_id")
    )


def _same_message(
    payload: dict,
    raw: bytes,
    *,
    folder: str,
    uid: int,
    flags: tuple[str, ...],
    raw_size: int,
    require_stable_id: bool = False,
) -> bool:
    """Match a fetched message against the approved one.

    The body hash is the primary proof. Some providers (Exchange) rewrite the
    stored bytes after delivery or a flag change, so a hash mismatch is accepted
    only when both the stable id and the provider Message-ID still match.
    """
    expected_hash = str(payload.get("raw_body_sha256") or "")
    expected_stable_id = str(payload.get("stable_message_id") or "")
    hash_ok = not expected_hash or hashlib.sha256(raw).hexdigest() == expected_hash
    if not hash_ok and not _message_id_anchored(payload):
        return False
    if hash_ok and not expected_stable_id and not require_stable_id:
        return True
    parsed = parse_message(
        account=str(payload.get("account") or ""),
        folder=folder,
        uid=uid,
        raw=raw,
        flags=flags,
        raw_size=raw_size,
    )
    if parsed.stable_id != expected_stable_id:
        return False
    if not hash_ok:
        expected_message_id = normalize_message_id(str(payload["provider_message_id"]))
        return normalize_message_id(parsed.message_id) == expected_message_id
    return True


MAX_RECONCILIATION_CANDIDATES = 500
# Bounded fallback when a provider (iCloud) does not index Message-ID headers.
MAX_RECONCILIATION_FALLBACK_CANDIDATES = 20
_FLAGS = {
    "seen": ("\\Seen", True),
    "unseen": ("\\Seen", False),
    "flag": ("\\Flagged", True),
    "unflag": ("\\Flagged", False),
}


@dataclasses.dataclass(frozen=True)
class LocatedMessage:
    uid_validity: str
    uid: int
    raw: bytes
    flags: tuple[str, ...]
    raw_size: int


class OAuthAccessToken(Protocol):
    def __call__(self, account: AccountConfig, *, force_refresh: bool = False) -> str: ...


class ImapFactory(Protocol):
    def __call__(self, host: str, port: int, timeout: int = 30): ...


class SmtpFactory(Protocol):
    def __call__(self, host: str, port: int, **kwargs): ...


_IMAP_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _imap_date(value: dt.datetime) -> str:
    """RFC 3501 date; strftime %b is locale-dependent and must not be used."""
    return f"{value.day:02d}-{_IMAP_MONTHS[value.month - 1]}-{value.year:04d}"


def _imap_string(value: str) -> str:
    if "\r" in value or "\n" in value:
        raise ProviderDefinitelyRejected("IMAP search identity is malformed")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _message_id(value: str) -> str:
    normalized = normalize_message_id(value)
    if not normalized or any(character in normalized for character in "\r\n<>"):
        raise ProviderDefinitelyRejected("outbound message id is malformed")
    return f"<{normalized}>"


class MailActionExecutor:
    """Provider-backed send/move/flag executor with identity-first reconciliation.

    The caller must pass the global writer fence before entering this class.
    No provider removal primitive is exposed here. Organization uses native
    IMAP MOVE, except for explicitly configured provider compatibility paths:
    COPY to an allowlisted destination while preserving the source and marking
    it Seen, or (UIDPLUS accounts) COPY, verify the copy, then flag and
    UID EXPUNGE only that one source message.
    """

    def __init__(
        self,
        *,
        accounts: tuple[AccountConfig, ...],
        archive: ArchiveReader,
        archive_writer: ArchiveWriter,
        credentials: CredentialStore,
        oauth_access_token: OAuthAccessToken,
        imap_factory: ImapFactory = imaplib.IMAP4_SSL,
        smtp_factory: SmtpFactory = smtplib.SMTP,
        smtp_ssl_factory: SmtpFactory = smtplib.SMTP_SSL,
        ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
        staged_attachments: StagedAttachmentStore | None = None,
        uidplus_move_accounts: frozenset[str] = frozenset(),
    ):
        self.accounts = {account.alias: account for account in accounts}
        self.archive = archive
        self.archive_writer = archive_writer
        self.credentials = credentials
        self.oauth_access_token = oauth_access_token
        self.imap_factory = imap_factory
        self.connector = ImapConnector(
            imap_factory=imap_factory,
            oauth_access_token=oauth_access_token,
            credentials=credentials,
        )
        self.smtp_factory = smtp_factory
        self.smtp_ssl_factory = smtp_ssl_factory
        self.ssl_context_factory = ssl_context_factory
        self.smtp_connector = SmtpConnector(
            smtp_factory=smtp_factory,
            smtp_ssl_factory=smtp_ssl_factory,
            ssl_context_factory=ssl_context_factory,
            oauth_access_token=oauth_access_token,
            credentials=credentials,
        )
        self.staged_attachments = staged_attachments
        self.uidplus_move_accounts = frozenset(uidplus_move_accounts)
        # Per-thread open connections while a ``session()`` is active.
        self._sessions = threading.local()

    def execute(self, payload: dict, idempotency_key: str) -> dict:
        operation = str(payload.get("operation") or "")
        if operation not in {
            "send",
            "reply",
            "forward",
            "archive",
            "move",
            "unrelated",
            "trash",
            "mark",
        }:
            raise ProviderDefinitelyRejected("approved mail operation is unsupported")
        with self._mailbox_guard(payload):
            if operation in {"send", "reply", "forward"}:
                return self._execute_send(payload, idempotency_key)
            if operation in {"archive", "move", "unrelated", "trash"}:
                return self._execute_move(payload)
            if operation == "mark":
                return self._execute_mark(payload)
            raise ProviderDefinitelyRejected("approved mail operation is unsupported")

    def reconcile(self, payload: dict, idempotency_key: str) -> dict | None:
        operation = str(payload.get("operation") or "")
        if operation not in {
            "send",
            "reply",
            "forward",
            "archive",
            "move",
            "unrelated",
            "trash",
            "mark",
        }:
            raise ProviderDefinitelyRejected("approved mail operation is unsupported")
        with self._mailbox_guard(payload):
            if operation in {"send", "reply", "forward"}:
                return self._reconcile_send(payload, idempotency_key)
            if operation in {"archive", "move", "unrelated", "trash"}:
                return self._reconcile_move(payload)
            if operation == "mark":
                return self._reconcile_mark(payload)
            raise ProviderDefinitelyRejected("approved mail operation is unsupported")

    @contextlib.contextmanager
    def _mailbox_guard(self, payload: dict):
        account = self._account(payload)
        # Cover provider mutation and local commit with the same account lock.
        with contextlib.ExitStack() as stack:
            try:
                stack.enter_context(
                    account_sync_lock(
                        self.archive_writer.data_dir, account.alias, wait_seconds=30.0
                    )
                )
            except MailboxSyncBusy as exc:
                raise ProviderNotAttempted(
                    "mailbox is busy; no provider operation was attempted"
                ) from exc
            yield

    def organization_capabilities(self, alias: str) -> dict:
        """Read authenticated IMAP capabilities; never write mail or authenticate SMTP."""
        account = self._account({"account": alias})
        try:
            with self._imap(account) as client:
                capabilities = self._capabilities(client, require_verified=True)
        except (imaplib.IMAP4.error, OSError) as exc:
            raise ProviderNotAttempted("provider IMAP capabilities could not be verified") from exc
        return {
            "account": account.alias,
            "native_move": "MOVE" in capabilities,
            "uidplus": "UIDPLUS" in capabilities,
            "copy_preserve_source_fallback": account.copy_preserve_source_fallback,
            "uidplus_move_fallback": account.alias in self.uidplus_move_accounts,
            "provider_mutations": 0,
        }

    def probe_account(self, alias: str) -> dict:
        """Authenticate and inspect capabilities without issuing a provider mutation."""
        account = self._account({"account": alias})
        folders = tuple(
            dict.fromkeys(
                (
                    *account.folders,
                    *account.safe_move_folders,
                    account.sent_folder,
                    account.trash_folder,
                )
            )
        )
        with self._imap(account) as client:
            capabilities = self._capabilities(client)
            for folder in folders:
                self._select(client, folder, readonly=True)
        smtp = None
        try:
            try:
                smtp = self._authenticated_smtp(account, force_refresh=False)
            except smtplib.SMTPAuthenticationError:
                if account.auth_kind != "oauth2":
                    raise
                smtp = self._authenticated_smtp(account, force_refresh=True)
        finally:
            if smtp is not None:
                with contextlib.suppress(Exception):
                    smtp.quit()
        uidplus_move = (
            "MOVE" not in capabilities
            and account.alias in self.uidplus_move_accounts
            and "UIDPLUS" in capabilities
        )
        return {
            "account": account.alias,
            "imap_authenticated": True,
            "folders_verified": len(folders),
            "native_move": "MOVE" in capabilities,
            "trash_folder_verified": True,
            "reversible_trash_ready": "MOVE" in capabilities or uidplus_move,
            "permanent_delete_supported": False,
            "copy_preserve_source_fallback": account.copy_preserve_source_fallback,
            "organization_ready": bool(
                "MOVE" in capabilities or uidplus_move or account.copy_preserve_source_fallback
            ),
            "organization_strategy": (
                "native_move"
                if "MOVE" in capabilities
                else "uidplus_expunge"
                if uidplus_move
                else (
                    "copy_preserve_source"
                    if account.copy_preserve_source_fallback
                    else "unavailable"
                )
            ),
            "smtp_authenticated": True,
            "smtp_mode": account.smtp_mode,
            "provider_mutations": 0,
        }

    def list_sent_metadata(
        self,
        alias: str,
        *,
        since: dt.datetime,
        before: dt.datetime,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Read bounded Sent headers directly without persisting or mutating provider mail."""
        if since.tzinfo is None or before.tzinfo is None or since >= before:
            raise ProviderDefinitelyRejected("Sent metadata time window is malformed")
        if not 1 <= limit <= 500:
            raise ProviderDefinitelyRejected("Sent metadata limit is out of range")
        account = self._account({"account": alias})
        since_utc = since.astimezone(dt.UTC)
        before_utc = before.astimezone(dt.UTC)
        with self._imap(account) as client:
            self._select(client, account.sent_folder, readonly=True)
            # SINCE compares server-local INTERNALDATE by day; start one day
            # early so a message near the boundary is not dropped — the Date
            # window filter below discards the extras.
            status, values = client.uid(
                "SEARCH",
                None,
                "SINCE",
                _imap_date(since_utc - dt.timedelta(days=1)),
            )
            if status != "OK":
                raise ProviderDefinitelyRejected("Sent metadata search was rejected")
            uids = [int(value) for value in (values[0] or b"").split()] if values else []
            rows: list[dict[str, Any]] = []
            for uid in reversed(uids[-limit:]):
                fetched = self._fetch_sent_header(client, uid)
                if fetched is None:
                    continue
                raw, flags, raw_size = fetched
                parsed = parse_message(
                    account=account.alias,
                    folder=account.sent_folder,
                    uid=uid,
                    raw=raw,
                    flags=flags,
                    raw_size=raw_size,
                )
                try:
                    received = dt.datetime.fromisoformat(
                        parsed.date_received.replace("Z", "+00:00")
                    )
                except ValueError:
                    continue
                if received.tzinfo is None:
                    continue
                received_utc = received.astimezone(dt.UTC)
                if not since_utc <= received_utc < before_utc:
                    continue
                rows.append(
                    {
                        "id": parsed.stable_id,
                        "account": parsed.account,
                        "folder": parsed.folder,
                        "sender_name": redact_text(parsed.sender_name)[:500],
                        "sender_email": redact_text(parsed.sender_email)[:500],
                        "recipients_to": redact_text(parsed.recipients_to)[:2000],
                        "recipients_cc": redact_text(parsed.recipients_cc)[:2000],
                        "subject": redact_text(parsed.subject)[:2000],
                        "date_received": parsed.date_received,
                        "flags": list(parsed.flags),
                    }
                )
        return sorted(rows, key=lambda item: item["date_received"], reverse=True)[:limit]

    def _account(self, payload: dict) -> AccountConfig:
        try:
            return self.accounts[str(payload["account"])]
        except (KeyError, TypeError) as exc:
            raise ProviderDefinitelyRejected("mail account is unknown or disabled") from exc

    def _authenticate_imap(self, account: AccountConfig):
        try:
            return self.connector.authenticate_interactive(account)
        except UnsupportedAuthKind as exc:
            raise ProviderDefinitelyRejected("mail authentication mode is unsupported") from exc

    @contextlib.contextmanager
    def session(self):
        """Reuse one authenticated IMAP connection per mailbox in this thread.

        A connection that raised is discarded, never reused. Nothing is expunged
        when a reused connection changes folders or closes: SELECT and LOGOUT
        deselect without EXPUNGE. Nested sessions share the outer one.
        """
        if getattr(self._sessions, "clients", None) is not None:
            yield
            return
        self._sessions.clients = {}
        try:
            yield
        finally:
            clients, self._sessions.clients = self._sessions.clients, None
            for client in clients.values():
                with contextlib.suppress(Exception):
                    client.logout()

    @staticmethod
    def _alive(client: Any) -> bool:
        try:
            return client.noop()[0] == "OK"
        except Exception:
            return False

    @contextlib.contextmanager
    def _imap(self, account: AccountConfig):
        clients = getattr(self._sessions, "clients", None)
        client = clients.pop(account.alias, None) if clients is not None else None
        if client is not None and not self._alive(client):
            with contextlib.suppress(Exception):
                client.logout()
            client = None
        if client is None:
            try:
                client = self._authenticate_imap(account)
            except ProviderDefinitelyRejected:
                raise
            except Exception as exc:
                # No mailbox command has run: connection, token refresh, credential
                # store and IMAP errors all leave the approval safely retryable.
                raise ProviderNotAttempted(
                    "IMAP connection or authentication failed before any mailbox operation"
                ) from exc
        reusable = False
        try:
            yield client
            reusable = clients is not None
        except ProviderNotAttempted:
            raise
        except ProviderDefinitelyRejected as exc:
            # A refused command or a failed identity check leaves the protocol
            # stream in step; transport errors and unknown outcomes never do.
            reusable = clients is not None and exc.__cause__ is None
            raise
        finally:
            if reusable:
                clients[account.alias] = client
            else:
                with contextlib.suppress(Exception):
                    client.logout()

    @staticmethod
    def _uid_validity(client: Any) -> str:
        response = client.response("UIDVALIDITY")
        if not response or not response[1] or not response[1][0]:
            raise ProviderNotAttempted("IMAP server omitted UIDVALIDITY")
        value = response[1][0]
        return value.decode() if isinstance(value, bytes) else str(value)

    def _select(self, client: Any, folder: str, *, readonly: bool) -> str:
        status, _data = client.select(_quote_folder(folder), readonly=readonly)
        if status != "OK":
            raise ProviderNotAttempted("approved IMAP folder is unavailable")
        return self._uid_validity(client)

    @staticmethod
    def _fetch(client: Any, uid: int) -> tuple[bytes, tuple[str, ...], int] | None:
        status, values = client.uid("FETCH", str(uid), "(UID FLAGS RFC822.SIZE BODY.PEEK[])")
        if status != "OK":
            raise ProviderNotAttempted("IMAP identity fetch was rejected")
        for item in values or []:
            if not (isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes)):
                continue
            metadata = (
                item[0].decode(errors="replace") if isinstance(item[0], bytes) else str(item[0])
            )
            match = re.search(r"\bUID\s+(\d+)\b", metadata, flags=re.I)
            if not match or int(match.group(1)) != uid:
                raise ProviderDefinitelyRejected("IMAP identity fetch returned a different UID")
            size_match = re.search(r"\bRFC822\.SIZE\s+(\d+)\b", metadata, flags=re.I)
            if not size_match:
                raise ProviderDefinitelyRejected("IMAP identity fetch omitted RFC822.SIZE")
            flags = _parse_fetch_flags(metadata)
            return item[1], flags, int(size_match.group(1))
        return None

    @staticmethod
    def _fetch_sent_header(client: Any, uid: int) -> tuple[bytes, tuple[str, ...], int] | None:
        fields = "DATE FROM TO CC SUBJECT MESSAGE-ID IN-REPLY-TO REFERENCES"
        status, values = client.uid(
            "FETCH",
            str(uid),
            f"(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS ({fields})])",
        )
        if status != "OK":
            raise ProviderDefinitelyRejected("Sent metadata fetch was rejected")
        for item in values or []:
            if not (isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes)):
                continue
            metadata = (
                item[0].decode(errors="replace") if isinstance(item[0], bytes) else str(item[0])
            )
            match = re.search(r"\bUID\s+(\d+)\b", metadata, flags=re.I)
            if not match or int(match.group(1)) != uid:
                raise ProviderDefinitelyRejected("Sent metadata fetch returned a different UID")
            size_match = re.search(r"\bRFC822\.SIZE\s+(\d+)\b", metadata, flags=re.I)
            if not size_match:
                raise ProviderDefinitelyRejected("Sent metadata fetch omitted RFC822.SIZE")
            flags = _parse_fetch_flags(metadata)
            return item[1], flags, int(size_match.group(1))
        return None

    def _candidate_uids(self, client: Any, payload: dict, *, fallback_recent: int = 0) -> list[int]:
        provider_message_id = str(payload.get("provider_message_id") or "")
        normalized_message_id = normalize_message_id(provider_message_id)
        if any(character in normalized_message_id for character in "\r\n"):
            raise ProviderDefinitelyRejected("IMAP search identity is malformed")
        header_search = bool(normalized_message_id) and not any(
            character in normalized_message_id for character in "<>"
        )
        if header_search:
            status, values = client.uid(
                "SEARCH",
                None,
                "HEADER",
                "Message-ID",
                _imap_string(f"<{normalized_message_id}>"),
            )
        else:
            status, values = client.uid("SEARCH", None, "ALL")
        if status != "OK":
            raise ProviderNotAttempted("IMAP reconciliation search was rejected")
        uids = [int(value) for value in (values[0] or b"").split()] if values else []
        if not uids and header_search and fallback_recent > 0:
            # Some providers do not index Message-ID; inspect only the newest
            # few messages and rely on the body hash and stable identity.
            status, values = client.uid("SEARCH", None, "ALL")
            if status != "OK":
                raise ProviderNotAttempted("IMAP reconciliation search was rejected")
            uids = [int(value) for value in (values[0] or b"").split()] if values else []
            return uids[-fallback_recent:]
        return uids[-MAX_RECONCILIATION_CANDIDATES:]

    def _locate(
        self, client: Any, folder: str, payload: dict, *, fallback_recent: int = 0
    ) -> LocatedMessage | None:
        uid_validity = self._select(client, folder, readonly=True)
        matches: list[LocatedMessage] = []
        for uid in self._candidate_uids(client, payload, fallback_recent=fallback_recent):
            fetched = self._fetch(client, uid)
            if fetched is None:
                continue
            raw, flags, raw_size = fetched
            if not _same_message(
                payload, raw, folder=folder, uid=uid, flags=flags, raw_size=raw_size
            ):
                continue
            matches.append(LocatedMessage(uid_validity, uid, raw, flags, raw_size))
        if len(matches) > 1:
            raise ProviderOutcomeUnknown("provider reconciliation found ambiguous copies")
        return matches[0] if matches else None

    def _source(self, client: Any, payload: dict) -> tuple[bytes, tuple[str, ...], int] | None:
        source = str(payload["source_folder"])
        uid_validity = self._select(client, source, readonly=False)
        if uid_validity != str(payload["source_uid_validity"]):
            raise ProviderDefinitelyRejected("source UIDVALIDITY changed after approval")
        uid = int(payload["source_uid"])
        fetched = self._fetch(client, uid)
        if fetched is None:
            return None
        raw, flags, raw_size = fetched
        expected_hash = str(payload.get("raw_body_sha256") or "")
        content_changed = bool(expected_hash) and hashlib.sha256(raw).hexdigest() != expected_hash
        if content_changed and not _message_id_anchored(payload):
            raise ProviderDefinitelyRejected("source message content changed after approval")
        parsed = parse_message(
            account=str(payload["account"]),
            folder=source,
            uid=uid,
            raw=raw,
            flags=flags,
            raw_size=raw_size,
        )
        if parsed.stable_id != str(payload["stable_message_id"]):
            raise ProviderDefinitelyRejected("source message identity changed after approval")
        expected_message_id = normalize_message_id(str(payload.get("provider_message_id") or ""))
        if expected_message_id and normalize_message_id(parsed.message_id) != expected_message_id:
            raise ProviderDefinitelyRejected("source Message-ID changed after approval")
        if content_changed:
            # Exchange (Outlook.com, Microsoft 365) rewrites stored bytes, e.g. on a flag
            # change; UIDVALIDITY+UID+Message-ID still pin the approved message.
            LOGGER.info(
                "source bytes differ from approval; identity verified by Message-ID account=%s",
                payload.get("account"),
            )
        return raw, flags, raw_size

    @staticmethod
    def _capabilities(client: Any, *, require_verified: bool = False) -> set[str]:
        status, values = client.capability()
        if require_verified and (status != "OK" or not values or not any(values)):
            raise ProviderNotAttempted("provider IMAP capabilities could not be verified")
        if status != "OK":
            return set()
        return {
            item.upper()
            for value in values or []
            for item in (
                value.decode(errors="replace") if isinstance(value, bytes) else str(value)
            ).split()
        }

    @staticmethod
    def _copy_uid(values: Any) -> int | None:
        text = " ".join(
            value.decode(errors="replace") if isinstance(value, bytes) else str(value)
            for value in (values or [])
        )
        match = re.search(r"COPYUID\s+\d+\s+\d+(?:[, :]\d+)*\s+(\d+)", text, flags=re.I)
        return int(match.group(1)) if match else None

    @staticmethod
    def _copy_uid_validity(values: Any) -> str | None:
        text = " ".join(
            value.decode(errors="replace") if isinstance(value, bytes) else str(value)
            for value in (values or [])
        )
        match = re.search(r"COPYUID\s+(\d+)\s+", text, flags=re.I)
        return match.group(1) if match else None

    def _execute_move(self, payload: dict) -> dict:
        account = self._account(payload)
        destination = str(payload["destination"])
        is_trash = payload.get("operation") == "trash"
        if is_trash:
            if destination.casefold() != account.trash_folder.casefold():
                raise ProviderDefinitelyRejected("mail Trash destination is not configured")
        elif destination.casefold() not in {item.casefold() for item in account.safe_move_folders}:
            raise ProviderDefinitelyRejected("mail destination is not allowlisted")
        strategy = self._organization_strategy(account, payload)
        with self._imap(account) as client:
            try:
                source = self._source(client, payload)
                if source is None:
                    reconciled = (
                        self._reconcile_copy_with_client(client, payload)
                        if strategy == "copy_preserve"
                        else self._reconcile_move_with_client(client, payload)
                    )
                    if reconciled:
                        return {**reconciled, "already_applied": True}
                    # No mailbox command was issued, so nothing was changed.
                    raise ProviderSourceGone(
                        "approved source message is gone and the destination does not hold it"
                    )
                capabilities = self._capabilities(client, require_verified=True)
            except (imaplib.IMAP4.error, OSError) as exc:
                raise ProviderNotAttempted(
                    "provider connection failed before any mailbox change"
                ) from exc
            if "MOVE" not in capabilities:
                if strategy == "uidplus":
                    if "UIDPLUS" not in capabilities:
                        raise ProviderDefinitelyRejected(
                            "provider lacks both IMAP MOVE and UIDPLUS"
                        )
                    return self._execute_uidplus_move(client, payload)
                if strategy == "copy_preserve":
                    return self._execute_copy_preserve_source(client, payload, source)
                raise ProviderDefinitelyRejected("provider lacks native IMAP MOVE support")
            try:
                status, values = client.uid(
                    "MOVE", str(int(payload["source_uid"])), _quote_folder(destination)
                )
            except (TimeoutError, OSError, imaplib.IMAP4.abort) as exc:
                raise ProviderOutcomeUnknown("provider MOVE outcome is unknown") from exc
            if status != "OK":
                raise ProviderDefinitelyRejected("provider rejected IMAP MOVE")
            destination_uid = self._copy_uid(values)
            try:
                verified = self._reconcile_move_with_client(client, payload)
            except Exception:
                # MOVE was acknowledged. A read-back failure cannot turn that
                # provider success into a definite rejection or a replay.
                verified = None
            if verified:
                return verified
            self._record_locally(
                "native_move",
                lambda: self.archive_writer.confirm_move(
                    str(payload["stable_message_id"]),
                    account=account.alias,
                    source=str(payload["source_folder"]),
                    destination=destination,
                    destination_uid=destination_uid,
                    destination_flags=source[1],
                ),
            )
            return {
                "status": "confirmed",
                "operation": str(payload["operation"]),
                "account": account.alias,
                "provider_object_id": str(payload["stable_message_id"]),
                "stable_message_id": str(payload["stable_message_id"]),
                "source_folder": str(payload["source_folder"]),
                "destination": destination,
                "source_uid": int(payload["source_uid"]),
                "destination_uid": destination_uid or 0,
                "verified": False,
            }

    @staticmethod
    def _record_locally(step: str, action: Callable[[], object]) -> None:
        """Update the local archive after a provider success; never fail the action."""
        try:
            action()
        except Exception as exc:
            LOGGER.warning(
                "approved action provider succeeded but local archive update failed "
                "step=%s error_class=%s",
                step,
                type(exc).__name__,
            )

    def _organization_strategy(self, account: AccountConfig, payload: dict) -> str:
        """Return the approved strategy, which must match the current account setup."""
        copy_preserve = self._copy_fallback(account, payload)
        declared = payload.get("uidplus_move_fallback", False)
        if (
            not isinstance(declared, bool)
            or declared != (account.alias in self.uidplus_move_accounts)
            or (declared and copy_preserve)
        ):
            raise ProviderDefinitelyRejected("approved organization strategy is malformed")
        return "copy_preserve" if copy_preserve else "uidplus" if declared else "native"

    @staticmethod
    def _declared_strategy(payload: dict) -> str:
        """Return the strategy recorded in the approval, for read-only reconciliation."""
        copy_preserve = payload.get("copy_preserve_source_fallback", False)
        uidplus = payload.get("uidplus_move_fallback", False)
        if (
            not isinstance(copy_preserve, bool)
            or not isinstance(uidplus, bool)
            or (copy_preserve and uidplus)
        ):
            raise ProviderDefinitelyRejected("approved organization strategy is malformed")
        return "copy_preserve" if copy_preserve else "uidplus" if uidplus else "native"

    def _reconcile_move(self, payload: dict) -> dict | None:
        account = self._account(payload)
        strategy = self._declared_strategy(payload)
        with self._imap(account) as client:
            return (
                self._reconcile_copy_with_client(client, payload, settle=True)
                if strategy == "copy_preserve"
                else self._reconcile_move_with_client(client, payload, settle=True)
            )

    def _raise_effect_absent(self, client: Any, payload: dict) -> None:
        """End an unproven outcome once reconciliation found no destination copy.

        Read-only. A missing source means the action can no longer apply. A
        source still at the approved UID proves nothing was applied only when
        the destination provably lacks a copy; otherwise this returns and the
        caller reports the outcome as still unknown, so it is never replayed.
        """
        if self._source_uid_absent(client, payload):
            raise ProviderSourceGone(
                "approved source message is gone and the destination does not hold it"
            )
        if self._destination_lacks_copy(client, payload):
            raise ProviderProvedNotApplied(
                "the source still holds the approved message and the destination does not"
            )

    def _destination_lacks_copy(self, client: Any, payload: dict) -> bool:
        """Read-only proof that no copy of the approved message reached the destination.

        Not finding the body hash proves nothing: a provider may re-encode a
        copied message (Exchange, Outlook.com), and an empty Message-ID search
        may only mean the provider does not index that header (iCloud). Absence
        is proven only when the destination holds no message with the approved
        Message-ID and the same search finds the source at its approved UID.
        """
        message_id = normalize_message_id(str(payload.get("provider_message_id") or ""))
        if not message_id or any(character in message_id for character in "<>\r\n"):
            return False
        _validity, destination_uids = self._message_id_uids(
            client, str(payload["destination"]), message_id
        )
        if destination_uids:
            return False
        source_validity, source_uids = self._message_id_uids(
            client, str(payload["source_folder"]), message_id
        )
        return (
            source_validity == str(payload["source_uid_validity"])
            and int(payload["source_uid"]) in source_uids
        )

    def _message_id_uids(self, client: Any, folder: str, message_id: str) -> tuple[str, set[int]]:
        uid_validity = self._select(client, folder, readonly=True)
        status, values = client.uid(
            "SEARCH", None, "HEADER", "Message-ID", _imap_string(f"<{message_id}>")
        )
        if status != "OK":
            raise ProviderNotAttempted("IMAP reconciliation search was rejected")
        return uid_validity, {
            int(value) for value in (values[0] or b"").split()
        } if values else set()

    def _verify_copied(
        self,
        client: Any,
        payload: dict,
        folder: str,
        uid: int | None,
        uid_validity: str | None,
    ) -> LocatedMessage | None:
        """Prove that ``folder`` holds the approved message, preferring COPYUID."""
        current_validity = self._select(client, folder, readonly=True)
        fetched = (
            self._fetch(client, uid)
            if uid is not None and uid_validity is not None and current_validity == uid_validity
            else None
        )
        if fetched is None:
            return self._locate(
                client, folder, payload, fallback_recent=MAX_RECONCILIATION_FALLBACK_CANDIDATES
            )
        raw, flags, raw_size = fetched
        if not _same_message(
            payload,
            raw,
            folder=folder,
            uid=uid,
            flags=flags,
            raw_size=raw_size,
            require_stable_id=True,
        ):
            return None
        return LocatedMessage(current_validity, uid, raw, flags, raw_size)

    def _source_uid_absent(self, client: Any, payload: dict) -> bool:
        """Read-only proof that the approved source message is gone."""
        folder = str(payload["source_folder"])
        if self._select(client, folder, readonly=True) == str(payload["source_uid_validity"]):
            if self._fetch(client, int(payload["source_uid"])) is not None:
                return False
        return self._locate(client, folder, payload) is None

    def _execute_uidplus_move(self, client: Any, payload: dict) -> dict:
        """COPY, verify the copy, then flag and UID EXPUNGE only the source UID."""
        destination = str(payload["destination"])
        uid = int(payload["source_uid"])
        copied = False
        copied_uid: int | None = None
        copied_validity: str | None = None
        try:
            existing = self._locate(
                client, destination, payload, fallback_recent=MAX_RECONCILIATION_FALLBACK_CANDIDATES
            )
        except (imaplib.IMAP4.error, OSError) as exc:
            raise ProviderNotAttempted(
                "provider connection failed before any mailbox change"
            ) from exc
        if existing is None:
            try:
                source = self._source(client, payload)
            except (imaplib.IMAP4.error, OSError) as exc:
                raise ProviderNotAttempted(
                    "provider connection failed before any mailbox change"
                ) from exc
            if source is None:
                raise ProviderSourceGone("approved source disappeared before provider COPY")
            try:
                status, values = client.uid("COPY", str(uid), _quote_folder(destination))
            except (TimeoutError, OSError, imaplib.IMAP4.abort) as exc:
                raise ProviderOutcomeUnknown("provider COPY outcome is unknown") from exc
            if status != "OK":
                raise ProviderDefinitelyRejected("provider rejected IMAP COPY")
            copied = True
            copied_uid = self._copy_uid(values)
            copied_validity = self._copy_uid_validity(values)
        unverified = "destination copy could not be verified; the source was kept"
        try:
            destination_copy = existing or self._verify_copied(
                client, payload, destination, copied_uid, copied_validity
            )
        except Exception as exc:
            raise ProviderOutcomeUnknown(unverified) from exc
        if destination_copy is None:
            raise ProviderOutcomeUnknown(unverified)
        try:
            current = self._source(client, payload)
        except Exception as exc:
            if copied:
                raise ProviderOutcomeUnknown(
                    "source could not be re-verified after COPY; the source was kept"
                ) from exc
            if isinstance(exc, (imaplib.IMAP4.error, OSError)):
                raise ProviderNotAttempted(
                    "provider connection failed before any mailbox change"
                ) from exc
            raise
        if current is not None:
            try:
                status, _values = client.uid("STORE", str(uid), "+FLAGS.SILENT", "(\\Deleted)")
            except Exception as exc:
                raise ProviderOutcomeUnknown("source deletion flag outcome is unknown") from exc
            if status != "OK":
                raise ProviderPartialOutcome(
                    "destination copy verified but the source deletion flag was rejected"
                )
            try:
                # UID EXPUNGE (RFC 4315) removes only this UID, never other
                # messages that happen to carry \Deleted in the same folder.
                status, _values = client.uid("EXPUNGE", str(uid))
            except Exception as exc:
                raise ProviderOutcomeUnknown("source UID EXPUNGE outcome is unknown") from exc
            if status != "OK":
                raise ProviderPartialOutcome(
                    "source is flagged deleted but UID EXPUNGE was rejected"
                )
        try:
            still_present = self._fetch(client, uid) is not None
        except Exception as exc:
            raise ProviderOutcomeUnknown("source is still present after UID EXPUNGE") from exc
        if still_present:
            raise ProviderOutcomeUnknown("source is still present after UID EXPUNGE")
        self._record_locally("uidplus_move", lambda: self._archive_moved(payload, destination_copy))
        result = {
            "status": "confirmed",
            "operation": str(payload["operation"]),
            "account": str(payload["account"]),
            "provider_object_id": str(payload["stable_message_id"]),
            "stable_message_id": str(payload["stable_message_id"]),
            "source_folder": str(payload["source_folder"]),
            "destination": destination,
            "source_uid": uid,
            "destination_uid": destination_copy.uid,
            "verified": True,
            "strategy": "uidplus_expunge",
        }
        if current is None:
            result["already_applied"] = True
        return result

    def _archive_moved(self, payload: dict, destination: LocatedMessage) -> None:
        self.archive_writer.upsert(
            parse_message(
                account=str(payload["account"]),
                folder=str(payload["destination"]),
                uid=destination.uid,
                raw=destination.raw,
                flags=destination.flags,
                raw_size=destination.raw_size,
            ),
            uid_validity=destination.uid_validity,
        )
        self.archive_writer.confirm_move(
            str(payload["stable_message_id"]),
            account=str(payload["account"]),
            source=str(payload["source_folder"]),
            destination=str(payload["destination"]),
            destination_uid=destination.uid,
            destination_uid_validity=destination.uid_validity,
            destination_flags=destination.flags,
        )

    @staticmethod
    def _copy_fallback(account: AccountConfig, payload: dict) -> bool:
        declared = payload.get("copy_preserve_source_fallback")
        expected = (
            False if payload.get("operation") == "trash" else account.copy_preserve_source_fallback
        )
        if not isinstance(declared, bool) or declared != expected:
            raise ProviderDefinitelyRejected("approved organization strategy is malformed")
        return declared

    def _execute_copy_preserve_source(
        self,
        client: Any,
        payload: dict,
        source: tuple[bytes, tuple[str, ...], int],
    ) -> dict:
        destination = str(payload["destination"])
        try:
            existing = self._locate(client, destination, payload)
        except (imaplib.IMAP4.error, OSError) as exc:
            raise ProviderNotAttempted(
                "provider connection failed before any mailbox change"
            ) from exc
        if existing:
            current_source = self._source(client, payload)
            if current_source is None:
                raise ProviderOutcomeUnknown(
                    "destination copy exists but the preserved source is absent"
                )
            if "\\Seen" not in current_source[1]:
                self._mark_source_seen_after_copy(client, payload)
            reconciled = self._reconcile_copy_with_client(client, payload)
            if reconciled:
                return {**reconciled, "already_applied": True}
            raise ProviderOutcomeUnknown("destination copy exists but its identity is unverified")
        try:
            source = self._source(client, payload)
        except (imaplib.IMAP4.error, OSError) as exc:
            raise ProviderNotAttempted(
                "provider connection failed before any mailbox change"
            ) from exc
        if source is None:
            raise ProviderSourceGone("approved source disappeared before provider COPY")
        try:
            status, values = client.uid(
                "COPY", str(int(payload["source_uid"])), _quote_folder(destination)
            )
        except (TimeoutError, OSError, imaplib.IMAP4.abort) as exc:
            raise ProviderOutcomeUnknown("provider COPY outcome is unknown") from exc
        if status != "OK":
            raise ProviderDefinitelyRejected("provider rejected non-destructive IMAP COPY")
        destination_uid = self._copy_uid(values)
        marked_source = self._mark_source_seen_after_copy(client, payload)
        try:
            verified = self._reconcile_copy_with_client(client, payload)
        except Exception:
            verified = None
        if verified:
            return verified

        def record() -> None:
            self.archive_writer.confirm_move(
                str(payload["stable_message_id"]),
                account=str(payload["account"]),
                source=str(payload["source_folder"]),
                destination=destination,
                destination_uid=destination_uid,
                destination_flags=source[1],
                source_preserved=True,
            )
            self.archive_writer.observe_location(
                parse_message(
                    account=str(payload["account"]),
                    folder=str(payload["source_folder"]),
                    uid=int(payload["source_uid"]),
                    raw=marked_source[0],
                    flags=marked_source[1],
                    raw_size=marked_source[2],
                ),
                uid_validity=str(payload["source_uid_validity"]),
            )

        self._record_locally("copy_preserve", record)
        return {
            "status": "confirmed",
            "operation": str(payload["operation"]),
            "account": str(payload["account"]),
            "provider_object_id": str(payload["stable_message_id"]),
            "stable_message_id": str(payload["stable_message_id"]),
            "source_folder": str(payload["source_folder"]),
            "destination": destination,
            "source_uid": int(payload["source_uid"]),
            "destination_uid": destination_uid or 0,
            "verified": False,
            "source_preserved": True,
            "source_seen": True,
            "degraded_copy": True,
        }

    def _mark_source_seen_after_copy(
        self, client: Any, payload: dict
    ) -> tuple[bytes, tuple[str, ...], int]:
        try:
            status, _values = client.uid(
                "STORE", str(int(payload["source_uid"])), "+FLAGS.SILENT", "(\\Seen)"
            )
        except Exception as exc:
            raise ProviderPartialOutcome(
                "destination COPY succeeded but source seen-state is unknown"
            ) from exc
        if status != "OK":
            raise ProviderPartialOutcome(
                "destination COPY succeeded but source seen-state was rejected"
            )
        try:
            marked_source = self._source(client, payload)
        except Exception as exc:
            raise ProviderPartialOutcome(
                "destination COPY succeeded but source seen-state was not verified"
            ) from exc
        if marked_source is None or "\\Seen" not in marked_source[1]:
            raise ProviderPartialOutcome(
                "destination COPY succeeded but source seen-state was not verified"
            )
        return marked_source

    def _reconcile_move_with_client(
        self, client: Any, payload: dict, *, settle: bool = False
    ) -> dict | None:
        destination = self._locate(
            client,
            str(payload["destination"]),
            payload,
            fallback_recent=MAX_RECONCILIATION_FALLBACK_CANDIDATES,
        )
        if destination is None and settle:
            self._raise_effect_absent(client, payload)
        if not destination or not self._source_uid_absent(client, payload):
            return None
        destination_uid = destination.uid
        self._record_locally("reconcile_move", lambda: self._archive_moved(payload, destination))
        return {
            "status": "confirmed",
            "operation": str(payload["operation"]),
            "account": str(payload["account"]),
            "provider_object_id": str(payload["stable_message_id"]),
            "stable_message_id": str(payload["stable_message_id"]),
            "source_folder": str(payload["source_folder"]),
            "destination": str(payload["destination"]),
            "source_uid": int(payload["source_uid"]),
            "destination_uid": destination_uid,
            "verified": True,
            "reconciled": True,
        }

    def _reconcile_copy_with_client(
        self, client: Any, payload: dict, *, settle: bool = False
    ) -> dict | None:
        destination = self._locate(
            client,
            str(payload["destination"]),
            payload,
            fallback_recent=MAX_RECONCILIATION_FALLBACK_CANDIDATES,
        )
        if destination is None and settle:
            self._raise_effect_absent(client, payload)
        source = self._locate(
            client,
            str(payload["source_folder"]),
            payload,
            fallback_recent=MAX_RECONCILIATION_FALLBACK_CANDIDATES,
        )
        if not destination or not source:
            return None

        def record() -> None:
            self.archive_writer.upsert(
                parse_message(
                    account=str(payload["account"]),
                    folder=str(payload["destination"]),
                    uid=destination.uid,
                    raw=destination.raw,
                    flags=destination.flags,
                    raw_size=destination.raw_size,
                ),
                uid_validity=destination.uid_validity,
            )
            self.archive_writer.observe_location(
                parse_message(
                    account=str(payload["account"]),
                    folder=str(payload["source_folder"]),
                    uid=source.uid,
                    raw=source.raw,
                    flags=source.flags,
                    raw_size=source.raw_size,
                ),
                uid_validity=source.uid_validity,
            )
            self.archive_writer.confirm_move(
                str(payload["stable_message_id"]),
                account=str(payload["account"]),
                source=str(payload["source_folder"]),
                destination=str(payload["destination"]),
                destination_uid=destination.uid,
                destination_uid_validity=destination.uid_validity,
                destination_flags=destination.flags,
                source_preserved=True,
            )

        self._record_locally("reconcile_copy", record)
        return {
            "status": "confirmed",
            "operation": str(payload["operation"]),
            "account": str(payload["account"]),
            "provider_object_id": str(payload["stable_message_id"]),
            "stable_message_id": str(payload["stable_message_id"]),
            "source_folder": str(payload["source_folder"]),
            "destination": str(payload["destination"]),
            "source_uid": int(payload["source_uid"]),
            "destination_uid": destination.uid,
            "verified": True,
            "reconciled": True,
            "source_preserved": True,
            "source_seen": "\\Seen" in source.flags,
            "degraded_copy": True,
        }

    def _execute_mark(self, payload: dict) -> dict:
        account = self._account(payload)
        try:
            flag, enabled = _FLAGS[str(payload["action"])]
        except KeyError as exc:
            raise ProviderDefinitelyRejected("mail mark action is not allowlisted") from exc
        with self._imap(account) as client:
            try:
                source = self._source(client, payload)
            except (imaplib.IMAP4.error, OSError) as exc:
                raise ProviderNotAttempted(
                    "provider connection failed before any mailbox change"
                ) from exc
            if source is None:
                raise ProviderSourceGone("approved source message is no longer present")
            _raw, flags, _raw_size = source
            if (flag in flags) is enabled:
                result = self._mark_result(payload, flags, reconciled=True)
                return {**result, "already_applied": True}
            operation = "+FLAGS.SILENT" if enabled else "-FLAGS.SILENT"
            try:
                status, _values = client.uid(
                    "STORE", str(int(payload["source_uid"])), operation, f"({flag})"
                )
            except (TimeoutError, OSError, imaplib.IMAP4.abort) as exc:
                raise ProviderOutcomeUnknown("provider flag outcome is unknown") from exc
            if status != "OK":
                raise ProviderDefinitelyRejected("provider rejected reversible flag mutation")
            try:
                verified = self._source(client, payload)
            except Exception as exc:
                raise ProviderOutcomeUnknown(
                    "provider acknowledged the flag but read-back failed"
                ) from exc
            if verified is None:
                raise ProviderOutcomeUnknown(
                    "provider acknowledged the flag but its outcome is unknown"
                )
            _raw, current, _raw_size = verified
            if (flag in current) is not enabled:
                raise ProviderOutcomeUnknown(
                    "provider acknowledged the flag but its state was not verified"
                )
            self._record_locally(
                "mark_flags", lambda: self._record_mark_flags(account, payload, current)
            )
            return self._mark_result(payload, current, reconciled=False)

    def _reconcile_mark(self, payload: dict) -> dict | None:
        account = self._account(payload)
        try:
            flag, enabled = _FLAGS[str(payload["action"])]
        except KeyError as exc:
            raise ProviderDefinitelyRejected("mail mark action is not allowlisted") from exc
        with self._imap(account) as client:
            source = self._source(client, payload)
            if source is None:
                raise ProviderSourceGone("approved source message is no longer present")
            _raw, flags, _raw_size = source
            if (flag in flags) is not enabled:
                raise ProviderProvedNotApplied("the approved flag state is not present")
            self._record_locally(
                "mark_flags", lambda: self._record_mark_flags(account, payload, flags)
            )
            return self._mark_result(payload, flags, reconciled=True)

    def _record_mark_flags(
        self, account: AccountConfig, payload: dict, flags: tuple[str, ...]
    ) -> None:
        if account.copy_preserve_source_fallback or account.alias in self.uidplus_move_accounts:
            self.archive_writer.update_location_flags(
                str(payload["stable_message_id"]),
                account=account.alias,
                folder=str(payload["source_folder"]),
                uid=int(payload["source_uid"]),
                flags=flags,
            )
            return
        self.archive_writer.update_flags(
            str(payload["stable_message_id"]), account=account.alias, flags=flags
        )

    @staticmethod
    def _mark_result(payload: dict, flags: tuple[str, ...], *, reconciled: bool) -> dict:
        flag, enabled = _FLAGS[str(payload["action"])]
        return {
            "status": "confirmed",
            "operation": "mark",
            "account": str(payload["account"]),
            "provider_object_id": str(payload["stable_message_id"]),
            "stable_message_id": str(payload["stable_message_id"]),
            "source_folder": str(payload["source_folder"]),
            "source_uid": int(payload["source_uid"]),
            "flag": flag,
            "enabled": enabled,
            "verified": (flag in flags) is enabled,
            "reconciled": reconciled,
        }

    def _build_message(self, payload: dict) -> tuple[EmailMessage, list[str]]:
        recipients_by_field: dict[str, list[str]] = {}
        for field in ("to", "cc", "bcc"):
            value = payload.get(field, [])
            if not isinstance(value, list) or len(value) > 50:
                raise ProviderDefinitelyRejected("approved recipient list is malformed")
            recipients_by_field[field] = []
            for item in value:
                address = str(item)
                if (
                    "\r" in address
                    or "\n" in address
                    or len(address) > 320
                    or not re.fullmatch(r"[^@\s]+@[^@\s]+", address)
                ):
                    raise ProviderDefinitelyRejected("approved recipient address is malformed")
                recipients_by_field[field].append(address)
        if not recipients_by_field["to"]:
            raise ProviderDefinitelyRejected("approved message has no primary recipient")
        subject = str(payload.get("subject") or "")
        body = str(payload.get("body") or "")
        attachments = payload.get("attachments", [])
        if (
            not subject
            or len(subject) > 998
            or "\r" in subject
            or "\n" in subject
            or not body
            or len(body) > 100000
            or not isinstance(attachments, list)
            or len(attachments) > 20
        ):
            raise ProviderDefinitelyRejected("approved message content is malformed")
        message = EmailMessage(policy=email.policy.SMTP)
        message["From"] = str(payload["from"])
        message["To"] = ", ".join(recipients_by_field["to"])
        if recipients_by_field["cc"]:
            message["Cc"] = ", ".join(recipients_by_field["cc"])
        message["Subject"] = subject
        prepared_at = dt.datetime.fromisoformat(str(payload["date"]).replace("Z", "+00:00"))
        if prepared_at.tzinfo is None:
            raise ProviderDefinitelyRejected("approved message date must include a timezone")
        message["Date"] = format_datetime(prepared_at)
        message["Message-ID"] = _message_id(str(payload["message_id"]))
        if payload.get("in_reply_to"):
            message["In-Reply-To"] = _message_id(str(payload["in_reply_to"]))
        references = [_message_id(str(item)) for item in payload.get("references", []) if item]
        if references:
            message["References"] = " ".join(references)
        message.set_content(body)
        for reference in attachments:
            if reference.get("staged_attachment_id"):
                if self.staged_attachments is None:
                    raise ProviderDefinitelyRejected("staged attachment storage is unavailable")
                try:
                    content, filename, mimetype = self.staged_attachments.content(reference)
                except StagedAttachmentError as exc:
                    raise ProviderDefinitelyRejected(str(exc)) from exc
            else:
                downloaded = self.archive.download_attachment(
                    str(reference["message_id"]), str(reference["attachment_id"])
                )
                content = base64.b64decode(str(downloaded["content_base64"]), validate=True)
                filename = str(downloaded["filename"])
                mimetype = str(downloaded["mimetype"])
            maintype, subtype = mimetype.split("/", 1)
            message.add_attachment(
                content,
                maintype=maintype,
                subtype=subtype,
                filename=filename,
            )
        if message.is_multipart():
            boundary_seed = hashlib.sha256(str(payload["message_id"]).encode()).hexdigest()[:32]
            message.set_boundary(f"===============evergarden-{boundary_seed}==")
        recipients = []
        seen_recipients: set[str] = set()
        for field in ("to", "cc", "bcc"):
            for item in recipients_by_field[field]:
                if item.casefold() not in seen_recipients:
                    recipients.append(item)
                    seen_recipients.add(item.casefold())
        return message, recipients

    def _smtp_send(
        self, account: AccountConfig, message: EmailMessage, recipients: list[str]
    ) -> None:
        smtp = None
        submission_started = False
        try:
            try:
                smtp = self._authenticated_smtp(account, force_refresh=False)
            except smtplib.SMTPAuthenticationError:
                if account.auth_kind != "oauth2":
                    raise
                smtp = self._authenticated_smtp(account, force_refresh=True)
            submission_started = True
            refused = smtp.send_message(
                message,
                from_addr=str(message["From"]),
                to_addrs=recipients,
            )
            if refused:
                # send_message returns a mapping only when at least one RCPT was
                # refused and at least one may have been accepted. Retrying the
                # whole message could duplicate delivery for accepted peers.
                raise ProviderPartialOutcome("SMTP partial recipient outcome is unknown")
        except ProviderOutcomeUnknown:
            raise
        except ProviderDefinitelyRejected:
            raise
        except (
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
            smtplib.SMTPDataError,
        ) as exc:
            raise ProviderDefinitelyRejected(
                "SMTP provider definitely rejected the message"
            ) from exc
        except smtplib.SMTPAuthenticationError as exc:
            if submission_started:
                raise ProviderOutcomeUnknown("SMTP submission outcome is unknown") from exc
            raise ProviderNotAttempted("SMTP authentication was rejected") from exc
        except Exception as exc:
            if submission_started:
                raise ProviderOutcomeUnknown("SMTP submission outcome is unknown") from exc
            raise ProviderNotAttempted("SMTP preflight failed before submission") from exc
        finally:
            if smtp is not None:
                with contextlib.suppress(Exception):
                    smtp.quit()

    def _authenticated_smtp(self, account: AccountConfig, *, force_refresh: bool):
        try:
            return self.smtp_connector.connect(account, force_refresh=force_refresh)
        except UnsupportedSmtpMode as exc:
            raise ProviderDefinitelyRejected("SMTP transport mode is unsupported") from exc

    def _sent_copy(self, account: AccountConfig, payload: dict) -> LocatedMessage | None:
        lookup = {
            "account": account.alias,
            "provider_message_id": str(payload["message_id"]),
        }
        with self._imap(account) as client:
            return self._locate(client, account.sent_folder, lookup)

    def _archive_sent_copy(
        self,
        account: AccountConfig,
        located: LocatedMessage,
    ) -> None:
        self.archive_writer.upsert(
            parse_message(
                account=account.alias,
                folder=account.sent_folder,
                uid=located.uid,
                raw=located.raw,
                flags=located.flags,
                raw_size=located.raw_size,
            ),
            uid_validity=located.uid_validity,
        )

    def _append_sent_copy(self, account: AccountConfig, message: EmailMessage) -> str:
        try:
            with self._imap(account) as client:
                status, _values = client.append(
                    _quote_folder(account.sent_folder),
                    "(\\Seen)",
                    None,
                    message.as_bytes(policy=email.policy.SMTP),
                )
        except (TimeoutError, OSError, imaplib.IMAP4.abort):
            return "append-outcome-unknown"
        except Exception:
            return "append-unavailable"
        return "append-accepted" if status == "OK" else "append-rejected"

    def _execute_send(self, payload: dict, idempotency_key: str) -> dict:
        account = self._account(payload)
        allowed_from = {address.casefold() for address in account.allowed_from_addresses}
        if str(payload["from"]).casefold() not in allowed_from:
            raise ProviderDefinitelyRejected(
                "approved From identity is not allowlisted for the account"
            )
        try:
            existing = self._sent_copy(account, payload)
        except ProviderOutcomeUnknown:
            raise
        except Exception as exc:
            raise ProviderNotAttempted("Sent preflight was unavailable before submission") from exc
        if existing:
            self._record_locally("sent_copy", lambda: self._archive_sent_copy(account, existing))
            self._consume_staged(payload)
            return self._send_result(
                payload,
                idempotency_key,
                sent_copy=True,
                sent_copy_state="verified",
                reconciled=True,
            )
        try:
            message, recipients = self._build_message(payload)
        except ProviderDefinitelyRejected:
            raise
        except Exception as exc:
            raise ProviderDefinitelyRejected("approved message is malformed") from exc
        self._smtp_send(account, message, recipients)
        self._consume_staged(payload)
        sent_copy = None
        sent_copy_state = "verification-unavailable"
        try:
            sent_copy = self._sent_copy(account, payload)
            if sent_copy:
                self._record_locally(
                    "sent_copy", lambda: self._archive_sent_copy(account, sent_copy)
                )
                sent_copy_state = "verified"
            else:
                sent_copy_state = "absent"
        except Exception:
            sent_copy_state = "verification-unavailable"
        if sent_copy is None and sent_copy_state == "absent":
            sent_copy_state = self._append_sent_copy(account, message)
            try:
                sent_copy = self._sent_copy(account, payload)
                if sent_copy:
                    self._record_locally(
                        "sent_copy", lambda: self._archive_sent_copy(account, sent_copy)
                    )
                    sent_copy_state = "verified"
            except Exception:
                sent_copy = None
        return self._send_result(
            payload,
            idempotency_key,
            sent_copy=bool(sent_copy),
            sent_copy_state=sent_copy_state,
            reconciled=False,
        )

    def _consume_staged(self, payload: dict) -> None:
        if self.staged_attachments is not None:
            staged = self.staged_attachments
            self._record_locally(
                "staged_attachments",
                lambda: staged.consume(list(payload.get("attachments", []))),
            )

    def _reconcile_send(self, payload: dict, idempotency_key: str) -> dict | None:
        account = self._account(payload)
        sent_copy = self._sent_copy(account, payload)
        if not sent_copy:
            return None
        self._record_locally("sent_copy", lambda: self._archive_sent_copy(account, sent_copy))
        self._consume_staged(payload)
        return self._send_result(
            payload,
            idempotency_key,
            sent_copy=True,
            sent_copy_state="verified",
            reconciled=True,
        )

    @staticmethod
    def _send_result(
        payload: dict,
        idempotency_key: str,
        *,
        sent_copy: bool,
        sent_copy_state: str,
        reconciled: bool,
    ) -> dict:
        del idempotency_key
        message_id = _message_id(str(payload["message_id"]))
        return {
            "status": "confirmed",
            "operation": str(payload["operation"]),
            "account": str(payload["account"]),
            "provider_object_id": message_id,
            "message_id": message_id,
            "sent_copy_verified": sent_copy,
            "sent_copy_state": sent_copy_state,
            "reconciled": reconciled,
            "already_applied": reconciled,
        }
