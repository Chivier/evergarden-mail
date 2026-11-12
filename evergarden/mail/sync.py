from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import email
import email.policy
import fcntl
import hashlib
import imaplib
import json
import logging
import re
import tempfile
import threading
import time
import uuid
from email.header import decode_header, make_header
from pathlib import Path

from evergarden.archive.sqlite_archive import ArchiveWriter, StaleMailboxSnapshot
from evergarden.audit.redaction import redact_error_detail
from evergarden.auth.credential_store import CredentialStore
from evergarden.mail.diagnostics import SERVICE_VERSION
from evergarden.mail.imap_connector import (
    ImapConnector,
    ImapFactory,
    OAuthAccessToken,
    is_transient_auth_rejection,
)
from evergarden.mail.models import (
    MAX_STORED_ATTACHMENT_BYTES,
    AccountConfig,
    AttachmentRecord,
    MessageRecord,
    normalize_message_id,
    stable_message_id,
)
from evergarden.mail.parse import address_email, address_name, date_to_iso, html_to_text
from evergarden.mail.parse import parse_message as parse_headers_and_body

logger = logging.getLogger(__name__)


class _FolderRecords:
    """Private, unlinked staging so atomic folder sync does not buffer large mail in RAM."""

    def __init__(self, directory):
        self.file = tempfile.TemporaryFile(mode="w+", encoding="utf-8", dir=directory)
        self.count = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.file.close()

    def __len__(self):
        return self.count

    def append(self, record: MessageRecord):
        value = dataclasses.asdict(record)
        for attachment in value["attachments"]:
            if attachment["content"] is not None:
                attachment["content"] = base64.b64encode(attachment["content"]).decode("ascii")
        self.file.write(json.dumps(value) + "\n")
        self.count += 1

    def __iter__(self):
        self.file.seek(0)
        for line in self.file:
            value = json.loads(line)
            value["flags"] = tuple(value["flags"])
            value["references_ids"] = tuple(value["references_ids"])
            for attachment in value["attachments"]:
                if attachment["content"] is not None:
                    attachment["content"] = base64.b64decode(attachment["content"], validate=True)
            value["attachments"] = tuple(AttachmentRecord(**a) for a in value["attachments"])
            yield MessageRecord(**value)


class MailboxSyncIncomplete(RuntimeError):
    """A mailbox was partially synced and every configured folder was attempted."""

    def __init__(self, result: dict, failures: tuple[dict[str, str], ...]):
        self.result = result
        self.failures = failures
        super().__init__(
            f"mailbox sync incomplete for {result['account']}: {len(failures)} folder(s)"
        )


def _header(value: str | None) -> str:
    try:
        return str(make_header(decode_header(value or "")))
    except (LookupError, UnicodeDecodeError):
        return value or ""


def _body(
    message: email.message.EmailMessage,
) -> tuple[str, str, tuple[AttachmentRecord, ...]]:
    plain: list[str] = []
    html: list[str] = []
    attachments: list[AttachmentRecord] = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        disposition = part.get_content_disposition()
        if disposition == "attachment" or part.get_filename():
            payload = part.get_payload(decode=True)
            if payload is None:
                raw_payload = part.get_payload()
                payload = (
                    raw_payload.encode("utf-8", errors="replace")
                    if isinstance(raw_payload, str)
                    else b""
                )
            attachments.append(
                AttachmentRecord(
                    filename=_header(part.get_filename()),
                    mimetype=part.get_content_type(),
                    size=len(payload),
                    content=payload if len(payload) <= MAX_STORED_ATTACHMENT_BYTES else None,
                )
            )
            continue
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = part.get_payload(decode=True).decode("utf-8", errors="replace")
        target = plain if content_type == "text/plain" else html
        # Keep only the first body alternative. Selecting every alternative can
        # duplicate text, and the archive must classify the same raw MIME
        # message identically every time it is fetched.
        if not target:
            target.append(str(content))
    body_text = plain[0] if plain else ""
    body_html = html[0] if html else ""
    if not body_text and body_html:
        body_text = html_to_text(body_html)
    return body_text, body_html, tuple(attachments)


def parse_message(
    *,
    account: str,
    folder: str,
    uid: int,
    raw: bytes,
    flags: tuple[str, ...],
    raw_size: int | None = None,
) -> MessageRecord:
    server_size = len(raw) if raw_size is None else int(raw_size)
    if server_size < 0:
        raise ValueError("RFC822.SIZE cannot be negative")
    message = email.message_from_bytes(raw, policy=email.policy.default)
    parsed = parse_headers_and_body(raw)
    sender_raw = parsed.from_
    sender_name = address_name(sender_raw)
    sender_email = address_email(sender_raw)
    reply_to = parsed.headers.get("reply-to", "")
    recipients_to = parsed.to
    recipients_cc = parsed.cc
    recipients_bcc = parsed.headers.get("bcc", "")
    list_id = parsed.headers.get("list-id", "")
    date_received = date_to_iso(parsed.date)
    _parsed_text, _parsed_html, attachments = _body(message)
    body_text, body_html = parsed.text, parsed.html
    message_id = normalize_message_id(parsed.message_id)
    in_reply_to = normalize_message_id(parsed.in_reply_to)
    references_ids = tuple(
        item
        for item in (
            normalize_message_id(value) for value in re.findall(r"<([^>]+)>", parsed.references)
        )
        if item
    )
    subject = parsed.subject
    stable_id = stable_message_id(
        account=account,
        message_id=message_id,
        sender_email=sender_email,
        date_received=date_received,
        subject=subject,
        raw_size=server_size,
    )
    return MessageRecord(
        stable_id=stable_id,
        account=account,
        folder=folder,
        uid=uid,
        message_id=message_id,
        sender_raw=sender_raw,
        sender_name=sender_name,
        sender_email=sender_email,
        recipients_to=recipients_to,
        recipients_cc=recipients_cc,
        subject=subject,
        date_received=date_received,
        body_text=body_text,
        body_html=body_html,
        has_attachments=bool(attachments),
        flags=flags,
        raw_size=server_size,
        raw_body_sha256=hashlib.sha256(raw).hexdigest(),
        attachments=attachments,
        in_reply_to=in_reply_to,
        references_ids=references_ids,
        reply_to=reply_to,
        recipients_bcc=recipients_bcc,
        list_id=list_id,
    )


# A timeout or abort leaves the IMAP stream mid-response; never reuse it.
_CONNECTION_ERRORS = (TimeoutError, OSError, imaplib.IMAP4.abort)


def _discard_connection(client) -> None:
    shutdown = getattr(client, "shutdown", None)
    if callable(shutdown):
        with contextlib.suppress(Exception):
            shutdown()


SYNC_LOCK_WAIT_SECONDS = 15 * 60
_SYNC_THREAD_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_SYNC_THREAD_LOCKS_GUARD = threading.Lock()


class MailboxSyncBusy(RuntimeError):
    """Another sync of the same account did not finish within the wait bound."""


@contextlib.contextmanager
def account_sync_lock(data_dir, alias: str, *, wait_seconds: float = SYNC_LOCK_WAIT_SECONDS):
    """Serialise syncs of one account across threads and containers.

    Every archive write bumps one state version per account, so two concurrent
    syncs of the same account invalidate each other's folder snapshots
    (StaleMailboxSnapshot). The thread lock covers one process; the flock on a
    file in the shared archive directory covers the mcp and worker containers.
    """
    key = (str(data_dir), alias)
    with _SYNC_THREAD_LOCKS_GUARD:
        thread_lock = _SYNC_THREAD_LOCKS.setdefault(key, threading.Lock())
    deadline = time.monotonic() + wait_seconds
    if not thread_lock.acquire(timeout=wait_seconds):
        raise MailboxSyncBusy(f"another sync of {alias} is still running")
    try:
        lock_path = Path(data_dir) / f".sync-{alias}.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a") as handle:
            with contextlib.suppress(OSError):
                lock_path.chmod(0o600)
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise MailboxSyncBusy(f"another sync of {alias} is still running") from None
                    time.sleep(0.5)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        thread_lock.release()


class ReadOnlyMailboxSync:
    """IMAP sync surface deliberately omitting STORE/COPY/MOVE/EXPUNGE."""

    def __init__(
        self,
        *,
        archive: ArchiveWriter,
        credentials: CredentialStore,
        oauth_access_token: OAuthAccessToken,
        imap_factory: ImapFactory = imaplib.IMAP4_SSL,
    ):
        self.archive = archive
        self.credentials = credentials
        self.oauth_access_token = oauth_access_token
        self.imap_factory = imap_factory
        self.connector = ImapConnector(
            imap_factory=imap_factory,
            oauth_access_token=oauth_access_token,
            credentials=credentials,
        )

    def authenticate(self, account: AccountConfig):
        return self.connector.authenticate_background(account)

    def _tracked_sync(self, account: AccountConfig, operation, per_folder_limit: int) -> dict:
        run_id = str(uuid.uuid4())
        started_at = dt.datetime.now(dt.UTC).isoformat(timespec="microseconds")
        result = None
        reason = None
        try:
            result = operation(account, per_folder_limit=per_folder_limit)
            return result
        except MailboxSyncIncomplete as exc:
            result = exc.result
            raise
        except Exception as exc:
            auth_failed = isinstance(exc, imaplib.IMAP4.error) and (
                is_transient_auth_rejection(exc)
                or any(token in str(exc).casefold() for token in ("auth", "login", "credential"))
            )
            auth_failed = auth_failed or bool(getattr(exc, "reauthorization_required", False))
            reason = "AUTHENTICATION_FAILED" if auth_failed else "SYNC_FAILED"
            raise
        finally:
            folders = dict.fromkeys((*account.folders, *(result or {}).get("folders", {})))
            for folder in folders:
                detail = (result or {}).get("folders", {}).get(folder, {})
                ok = bool(detail) and detail.get("status") != "failed"
                self.archive.record_sync_attempt(
                    account.alias,
                    folder,
                    run_id,
                    "ok" if ok else "failed",
                    None if ok else detail.get("reason_code") or reason or "SYNC_FAILED",
                    started_at=started_at,
                )
            logger.info(
                "mail sync finished account=%s sync_run_id=%s service_version=%s",
                account.alias,
                run_id,
                SERVICE_VERSION,
            )

    def sync_account(self, account: AccountConfig, *, per_folder_limit: int = 500) -> dict:
        if not 1 <= per_folder_limit <= 5000:
            raise ValueError("per-folder sync limit must be between 1 and 5000")
        with account_sync_lock(self.archive.data_dir, account.alias):
            return self._tracked_sync(account, self._sync_account, per_folder_limit)

    def _sync_account(self, account: AccountConfig, *, per_folder_limit: int = 500) -> dict:
        if not 1 <= per_folder_limit <= 5000:
            raise ValueError("per-folder sync limit must be between 1 and 5000")
        client = self.authenticate(account)
        result = {"account": account.alias, "folders": {}, "inserted": 0, "auth": "ok"}
        failures: list[dict[str, str]] = []
        try:
            for folder in self._read_folders(client, account):
                try:
                    if client is None:
                        # The previous folder broke the connection; a fresh one
                        # keeps its undefined protocol state from failing this one.
                        client = self.authenticate(account)
                    folder_result = self._sync_folder(client, account, folder, per_folder_limit)
                except Exception as exc:
                    failure = {
                        "folder": folder,
                        "status": "failed",
                        "error_class": type(exc).__name__,
                        "error_detail": redact_error_detail(exc),
                    }
                    result["folders"][folder] = failure
                    failures.append(failure)
                    if client is not None and isinstance(exc, _CONNECTION_ERRORS):
                        _discard_connection(client)
                        client = None
                    continue
                result["folders"][folder] = folder_result
                result["inserted"] += folder_result["fetched"]
        finally:
            if client is not None:
                try:
                    client.logout()
                except (imaplib.IMAP4.error, OSError):
                    logger.warning("IMAP logout failed account=%s", account.alias)
        if failures:
            raise MailboxSyncIncomplete(result, tuple(failures))
        return result

    @staticmethod
    def _read_folders(client, account: AccountConfig) -> tuple[str, ...]:
        """Discover receive folders without extending any provider-write allowlist."""
        listing = getattr(client, "list", None)
        if not callable(listing):
            return account.folders
        status, values = listing()
        if status != "OK":
            raise RuntimeError(f"read-only LIST failed for {account.alias}")
        folders = list(account.folders)
        seen = {folder.casefold() for folder in folders}
        # Calendar/contact stores and outbound staging are separate from received mail.
        excluded = {"calendar", "contacts", "journal", "notes", "tasks", "outbox", "drafts"}
        excluded.update(
            {account.sent_folder.casefold(), "sent items", "sent mail", "[gmail]/sent mail"}
        )
        for value in values or []:
            try:
                if isinstance(value, tuple) and len(value) == 2:
                    value = value[0].rsplit(b" ", 1)[0] + b" " + value[1]
                if not isinstance(value, bytes):
                    raise RuntimeError(f"unrecognized LIST response for {account.alias}")
                match = re.fullmatch(rb'\((.*?)\)\s+(?:".*?"|NIL)\s+(.*)', value)
                if not match:
                    raise RuntimeError(f"unrecognized LIST response for {account.alias}")
                attributes = match[1].lower().split()
                if any(attribute in attributes for attribute in (b"\\noselect", b"\\nonexistent")):
                    continue
                name = match[2].decode("utf-8")
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                folder = _imap_utf7_decode(name)
            except (RuntimeError, UnicodeDecodeError, ValueError):
                logger.warning("skipped unreadable LIST entry account=%s", account.alias)
                continue
            key = folder.casefold()
            if key in seen:
                continue
            if (
                key.split("/", 1)[0] in excluded
                or key in excluded
                or any(attribute in attributes for attribute in (b"\\drafts", b"\\sent"))
            ):
                continue
            folders.append(folder)
            seen.add(key)
        return tuple(folders)

    def _sync_folder(
        self, client, account: AccountConfig, folder: str, per_folder_limit: int
    ) -> dict:
        return self._retry_folder_snapshot(
            self._read_sync_folder, client, account, folder, per_folder_limit
        )

    @staticmethod
    def _retry_folder_snapshot(operation, client, account, folder, per_folder_limit) -> dict:
        for attempt in range(3):
            try:
                result = operation(client, account, folder, per_folder_limit)
                result["snapshot_retries"] = attempt
                return result
            except StaleMailboxSnapshot:
                if attempt == 2:
                    raise
                logger.info(
                    "discarded superseded mailbox snapshot account=%s folder=%s",
                    account.alias,
                    folder,
                )
                # Re-select and re-read the whole folder after bounded backoff.
                # Provider moves can settle after our first consistent read.
                time.sleep((2.0, 5.0)[attempt])
        raise AssertionError("unreachable snapshot retry")

    def _read_sync_folder(
        self, client, account: AccountConfig, folder: str, per_folder_limit: int
    ) -> dict:
        version = self.archive.state_version(account.alias)
        status, data = client.select(_quote_folder(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"read-only SELECT failed for {account.alias}/{folder}")
        uid_validity = self._uid_validity(client, data)
        previous = self.archive.sync_state(account.alias, folder)
        if previous and previous[0] == uid_validity:
            last_uid = previous[1]
            uid_validity_changed = False
        elif previous:
            # UIDVALIDITY changed: old UIDs are unsafe as a watermark.
            last_uid = 0
            uid_validity_changed = True
        else:
            # An imported archive has a legacy sync_state but no
            # UIDVALIDITY. Adopt its high-water mark on first contact.
            last_uid = self.archive.initial_last_uid(account.alias, folder)
            uid_validity_changed = False
        current_uids, current_flags = self._current_folder_state(
            client, account.alias, folder, expected_count=self._select_count(data)
        )
        known_uids = self.archive.known_location_uids(account.alias, folder, uid_validity)
        new_uids = sorted(uid for uid in current_uids if uid > last_uid)
        historical_discoveries = sorted(
            uid for uid in current_uids if uid <= last_uid and uid not in known_uids
        )
        historical_discovery_set = set(historical_discoveries)
        # Preserve prompt receipt of genuinely new mail, then use remaining
        # capacity to discover MOVE destinations whose provider UID fell below
        # the existing high-water mark.
        uids = (new_uids + historical_discoveries)[:per_folder_limit]
        fetched_historical = sum(uid in historical_discovery_set for uid in uids)
        with _FolderRecords(self.archive.data_dir) as records:
            for uid in uids:
                status, fetched = client.uid(
                    "FETCH", str(uid), "(UID FLAGS RFC822.SIZE BODY.PEEK[])"
                )
                if status != "OK":
                    raise RuntimeError(f"UID FETCH failed for {account.alias}/{folder}")
                metadata, raw = self._fetch_parts(fetched)
                match = re.search(r"\bUID\s+(\d+)\b", metadata, flags=re.I)
                if not match or int(match.group(1)) != uid:
                    raise RuntimeError(f"UID FETCH identity mismatch for {account.alias}/{folder}")
                flags = _parse_fetch_flags(metadata)
                record = parse_message(
                    account=account.alias,
                    folder=folder,
                    uid=uid,
                    raw=raw,
                    flags=flags,
                    raw_size=self._rfc822_size(metadata),
                )
                records.append(record)
                last_uid = max(last_uid, uid)
            if records:
                checked_uids, current_flags = self._current_folder_state(
                    client, account.alias, folder, expected_count=len(current_uids)
                )
                if checked_uids != current_uids:
                    raise StaleMailboxSnapshot(
                        "provider folder changed while fetching message bodies"
                    )
            reconciled = self.archive.apply_folder_snapshot(
                account.alias,
                folder,
                uid_validity,
                current_uids,
                current_flags,
                records,
                expected_version=version,
                last_uid=last_uid,
            )
            return {
                "status": "ok",
                "fetched": len(records),
                "last_uid": last_uid,
                "uid_validity": uid_validity,
                "uid_validity_changed": uid_validity_changed,
                "historical_uid_discoveries": fetched_historical,
                "historical_uid_discoveries_remaining": max(
                    0, len(historical_discoveries) - fetched_historical
                ),
                "locations_deactivated": reconciled["deactivated"],
                "locations_reactivated": reconciled["reactivated"],
                "location_flags_updated": reconciled["flags_updated"],
                "identity_conflicts": reconciled["identity_conflicts"],
            }

    def _current_folder_state(
        self, client, account: str, folder: str, *, expected_count: int | None = None
    ) -> tuple[set[int], dict[int, tuple[str, ...]]]:
        status, values = client.uid("SEARCH", None, "ALL")
        if status != "OK":
            raise RuntimeError(f"UID SEARCH failed for {account}/{folder}")
        current_uids = {int(value) for value in (values[0] or b"").split() if value}
        if expected_count is not None and len(current_uids) != expected_count:
            raise StaleMailboxSnapshot(
                f"UID SEARCH snapshot incomplete or changed for {account}/{folder}"
            )
        if not current_uids:
            return set(), {}
        status, values = client.uid("FETCH", "1:*", "(UID FLAGS)")
        if status != "OK":
            raise RuntimeError(f"UID FLAGS fetch failed for {account}/{folder}")
        current_flags = self._fetch_flag_map(values)
        if set(current_flags) != current_uids:
            raise RuntimeError(f"UID FLAGS snapshot incomplete for {account}/{folder}")
        return current_uids, current_flags

    @staticmethod
    def _select_count(data) -> int:
        if (
            not data
            or len(data) != 1
            or not str(data[0].decode() if isinstance(data[0], bytes) else data[0]).isdigit()
        ):
            raise RuntimeError("IMAP server omitted SELECT message count")
        return int(data[0])

    @staticmethod
    def _uid_validity(client, select_data) -> str:
        response = client.response("UIDVALIDITY")
        if response and response[1] and response[1][0]:
            value = response[1][0]
            return value.decode() if isinstance(value, bytes) else str(value)
        del select_data
        raise RuntimeError("IMAP server omitted UIDVALIDITY")

    @staticmethod
    def _fetch_parts(values) -> tuple[str, bytes]:
        for item in values or []:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
                metadata = (
                    item[0].decode(errors="replace") if isinstance(item[0], bytes) else str(item[0])
                )
                return metadata, item[1]
        raise RuntimeError("IMAP FETCH response did not contain a message")

    @staticmethod
    def _rfc822_size(metadata: str) -> int:
        match = re.search(r"\bRFC822\.SIZE\s+(\d+)\b", metadata, flags=re.I)
        if not match:
            raise RuntimeError("IMAP FETCH response omitted RFC822.SIZE")
        return int(match.group(1))

    @staticmethod
    def _fetch_flag_map(values) -> dict[int, tuple[str, ...]]:
        result: dict[int, tuple[str, ...]] = {}
        for item in values or []:
            metadata = item[0] if isinstance(item, tuple) and item else item
            if isinstance(metadata, bytes):
                metadata = metadata.decode(errors="replace")
            text = str(metadata or "")
            uid_match = re.search(r"\bUID\s+(\d+)\b", text, flags=re.I)
            flags_match = re.search(r"\bFLAGS\s*\(([^)]*)\)", text, flags=re.I)
            if uid_match and flags_match:
                result[int(uid_match.group(1))] = tuple(flags_match.group(1).split())
        return result


def _imap_utf7_decode(value: str) -> str:
    def decode(match):
        encoded = match[1]
        if not encoded:
            return "&"
        return base64.b64decode(
            encoded.replace(",", "/") + "=" * ((-len(encoded)) % 4), validate=True
        ).decode("utf-16-be")

    return re.sub(r"&([^-]*)-", decode, value)


def _imap_utf7_encode(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "&":
            output.append("&-")
            index += 1
        elif 0x20 <= ord(character) <= 0x7E:
            output.append(character)
            index += 1
        else:
            end = index
            while end < len(value) and not (value[end] == "&" or 0x20 <= ord(value[end]) <= 0x7E):
                end += 1
            encoded = (
                base64.b64encode(value[index:end].encode("utf-16-be"))
                .decode("ascii")
                .rstrip("=")
                .replace("/", ",")
            )
            output.append(f"&{encoded}-")
            index = end
    return "".join(output)


def _parse_fetch_flags(metadata: str) -> tuple[str, ...]:
    """Extract the full FLAGS list from a FETCH metadata line.

    Keeps IMAP keywords ($Forwarded, Junk, custom labels) as well as
    backslash system flags, matching ``_fetch_flag_map`` — a lossy parse here
    makes fresh records disagree with snapshot flag maps and churns
    reconciliation. Falls back to system flags when no FLAGS group is present.
    """
    match = re.search(r"\bFLAGS\s*\(([^)]*)\)", metadata, flags=re.I)
    if match:
        return tuple(match.group(1).split())
    return tuple(re.findall(r"\\[A-Za-z]+", metadata))


def _quote_folder(value: str) -> str:
    encoded = _imap_utf7_encode(value)
    if any(character in encoded for character in ' ()"\\'):
        return '"' + encoded.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return encoded
