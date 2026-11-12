from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import email
import email.policy
import imaplib
import logging
import smtplib
import sqlite3
from collections.abc import Callable
from email.message import EmailMessage
from pathlib import Path

import pytest

from evergarden.approvals.models import Actor, ExecutionState, IntentKind
from evergarden.approvals.service import (
    ApprovalError,
    ApprovalRepository,
    ApprovalService,
    ProviderDefinitelyRejected,
    ProviderNotAttempted,
    ProviderOutcomeUnknown,
    ProviderPartialOutcome,
    ProviderProvedNotApplied,
    ProviderSourceGone,
)
from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter
from evergarden.auth.credential_store import CredentialStore, generate_key
from evergarden.auth.provider_oauth import OAuthTokenRequestError
from evergarden.automations.fence import FenceConfig, FenceRejected, LeaseToken, SideEffectFence
from evergarden.mail.actions import MailActionExecutor
from evergarden.mail.models import AccountConfig
from evergarden.mail.runtime import MailRuntime
from evergarden.mail.staged_attachments import StagedAttachmentError, StagedAttachmentStore
from evergarden.mail.sync import parse_message


def _raw_message(
    *,
    message_id: str = "<source@example.test>",
    subject: str = "Action source",
    attachment: bool = False,
) -> bytes:
    message = EmailMessage()
    message["From"] = "Alice <alice@example.test>"
    message["Reply-To"] = "team@example.test"
    message["To"] = "Sender <sender@example.test>"
    message["Subject"] = subject
    message["Message-ID"] = message_id
    message["Date"] = "Mon, 17 Aug 2026 10:00:00 +0000"
    message.set_content("Provider identity body")
    if attachment:
        message.add_attachment(
            b"%PDF-1.4\nattachment",
            maintype="application",
            subtype="pdf",
            filename="evidence.pdf",
        )
    return message.as_bytes(policy=email.policy.SMTP)


def _unquote(value: str) -> str:
    text = str(value)
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    return text.replace('\\"', '"').replace("\\\\", "\\")


class FakeMailProvider:
    def __init__(self):
        self.mailboxes: dict[str, dict[int, tuple[bytes, tuple[str, ...]]]] = {
            "INBOX": {},
            "Archive": {},
            "Unrelated": {},
            "Sent": {},
            "Trash": {},
        }
        self.uid_validity = {folder: "777" for folder in self.mailboxes}
        self.move_calls = 0
        self.copy_calls = 0
        self.store_calls = 0
        self.smtp_calls = 0
        self.smtp_from: str | None = None
        self.smtp_login_address: str | None = None
        self.append_calls = 0
        self.move_timeout_once = False
        self.copy_timeout_once = False
        self.copy_reject_once = False
        self.copy_defer_visibility = False
        self.store_timeout_once = False
        # Exchange rewrites a message's stored MIME bytes when its flags change.
        self.rewrite_on_store = False
        self.smtp_timeout_once = False
        self.smtp_refuse_once = False
        self.smtp_refuse_all_once = False
        self.smtp_defer_sent = False
        self.append_defer_visibility = False
        self.pending_sent: bytes | None = None
        self.pending_copy: tuple[str, int, bytes, tuple[str, ...]] | None = None
        self.imap_auth_fail_once = False
        self.smtp_auth_fail_once = False
        self.supports_move = True
        self.supports_uidplus = True
        self.expunge_reject_once = False
        self.expunge_calls = 0
        # iCloud does not index Message-ID headers for UID SEARCH HEADER.
        self.header_search_unindexed = False
        self.fetch_error_once: Exception | None = None
        self.smtp_recipients: list[str] = []
        self.imap_calls: list[tuple] = []

    def imap(self, *_args, **_kwargs):
        return FakeIMAP(self)

    def smtp(self, *_args, **_kwargs):
        return FakeSMTP(self)

    def next_uid(self, folder: str) -> int:
        return max(self.mailboxes[folder], default=0) + 1


class FakeIMAP:
    def __init__(self, provider: FakeMailProvider):
        self.provider = provider
        self.selected = "INBOX"
        self.readonly = True
        self.dead = False
        self.logged_out = False

    def noop(self):
        if self.dead:
            raise imaplib.IMAP4.abort("connection closed by server")
        return "OK", []

    def login(self, _address, _password):
        return "OK", []

    def authenticate(self, _mechanism, callback):
        callback(b"challenge")
        if self.provider.imap_auth_fail_once:
            self.provider.imap_auth_fail_once = False
            raise imaplib.IMAP4.error("expired token")
        return "OK", []

    def logout(self):
        self.logged_out = True
        return "BYE", []

    def select(self, folder, readonly=False):
        selected = _unquote(folder)
        self.provider.imap_calls.append(("select", selected, readonly))
        if selected not in self.provider.mailboxes:
            return "NO", []
        self.selected = selected
        self.readonly = readonly
        return "OK", [str(len(self.provider.mailboxes[selected])).encode()]

    def response(self, name):
        assert name == "UIDVALIDITY"
        return "UIDVALIDITY", [self.provider.uid_validity[self.selected].encode()]

    def capability(self):
        value = b"IMAP4rev1"
        if self.provider.supports_uidplus:
            value += b" UIDPLUS"
        if self.provider.supports_move:
            value += b" MOVE"
        return "OK", [value]

    def expunge(self):
        raise AssertionError("plain EXPUNGE would remove every \\Deleted message in the folder")

    def append(self, folder, _flags, _date, raw):
        destination = _unquote(folder)
        assert destination == "Sent"
        self.provider.append_calls += 1
        if self.provider.append_defer_visibility:
            self.provider.pending_sent = raw
        else:
            uid = self.provider.next_uid(destination)
            self.provider.mailboxes[destination][uid] = (raw, ("\\Seen",))
        return "OK", []

    def uid(self, command, *args):
        command = command.upper()
        self.provider.imap_calls.append(("uid", command, *args))
        if command == "SEARCH":
            rows = self.provider.mailboxes[self.selected]
            if args[-1] == "ALL":
                selected = sorted(rows)
            elif len(args) >= 2 and str(args[-2]).upper() == "SINCE":
                selected = sorted(rows)
            else:
                target = _unquote(args[-1]).casefold()
                selected = []
                if self.provider.header_search_unindexed:
                    rows = {}
                for uid, (raw, _flags) in rows.items():
                    parsed = email.message_from_bytes(raw, policy=email.policy.default)
                    if str(parsed.get("Message-ID") or "").casefold() == target:
                        selected.append(uid)
            return "OK", [" ".join(str(uid) for uid in selected).encode()]
        if command == "FETCH":
            if self.provider.fetch_error_once is not None:
                error, self.provider.fetch_error_once = self.provider.fetch_error_once, None
                raise error
            uid = int(args[0])
            row = self.provider.mailboxes[self.selected].get(uid)
            if row is None:
                return "OK", []
            raw, flags = row
            metadata = (
                f"1 (UID {uid} FLAGS ({' '.join(flags)}) RFC822.SIZE {len(raw)} BODY[] "
                f"{{{len(raw)}}}"
            ).encode()
            return "OK", [(metadata, raw), b")"]
        if command == "MOVE":
            assert not self.readonly
            uid = int(args[0])
            destination = _unquote(args[1])
            raw, flags = self.provider.mailboxes[self.selected].pop(uid)
            parsed = email.message_from_bytes(raw, policy=email.policy.default)
            message_id = str(parsed.get("Message-ID") or "").casefold()
            destination_uid = next(
                (
                    existing_uid
                    for existing_uid, (existing_raw, _existing_flags) in self.provider.mailboxes[
                        destination
                    ].items()
                    if str(
                        email.message_from_bytes(existing_raw, policy=email.policy.default).get(
                            "Message-ID"
                        )
                        or ""
                    ).casefold()
                    == message_id
                ),
                self.provider.next_uid(destination),
            )
            self.provider.mailboxes[destination].setdefault(destination_uid, (raw, flags))
            self.provider.move_calls += 1
            if self.provider.move_timeout_once:
                self.provider.move_timeout_once = False
                raise TimeoutError("MOVE accepted before timeout")
            return "OK", [f"[COPYUID 777 {uid} {destination_uid}]".encode()]
        if command == "COPY":
            assert not self.readonly
            uid = int(args[0])
            destination = _unquote(args[1])
            if self.provider.copy_reject_once:
                self.provider.copy_reject_once = False
                return "NO", [b"COPY rejected"]
            raw, flags = self.provider.mailboxes[self.selected][uid]
            destination_uid = self.provider.next_uid(destination)
            if self.provider.copy_defer_visibility:
                self.provider.pending_copy = (destination, destination_uid, raw, flags)
            else:
                self.provider.mailboxes[destination][destination_uid] = (raw, flags)
            self.provider.copy_calls += 1
            if self.provider.copy_timeout_once:
                self.provider.copy_timeout_once = False
                raise TimeoutError("COPY accepted before timeout")
            validity = self.provider.uid_validity[destination]
            return "OK", [f"[COPYUID {validity} {uid} {destination_uid}]".encode()]
        if command == "STORE":
            assert not self.readonly
            uid = int(args[0])
            operation = str(args[1])
            requested = str(args[2]).strip("()").split()
            raw, flags = self.provider.mailboxes[self.selected][uid]
            updated = set(flags)
            if operation.startswith("+"):
                updated.update(requested)
            else:
                updated.difference_update(requested)
            if self.provider.rewrite_on_store:
                raw = raw.replace(b"Provider identity body", b"Provider regenerated body")
            self.provider.mailboxes[self.selected][uid] = (raw, tuple(sorted(updated)))
            self.provider.store_calls += 1
            if self.provider.store_timeout_once:
                self.provider.store_timeout_once = False
                raise TimeoutError("STORE accepted before timeout")
            return "OK", []
        if command == "EXPUNGE":
            assert not self.readonly
            self.provider.expunge_calls += 1
            if self.provider.expunge_reject_once:
                self.provider.expunge_reject_once = False
                return "NO", [b"EXPUNGE rejected"]
            rows = self.provider.mailboxes[self.selected]
            for uid in (int(item) for item in str(args[0]).split(",")):
                if uid in rows and "\\Deleted" in rows[uid][1]:
                    del rows[uid]
            return "OK", []
        raise AssertionError(command)


class FakeSMTP:
    def __init__(self, provider: FakeMailProvider):
        self.provider = provider

    def ehlo(self):
        return 250, b"ok"

    def starttls(self, **_kwargs):
        return 220, b"ready"

    def login(self, address, _password):
        self.provider.smtp_login_address = str(address)
        return 235, b"ok"

    def auth(self, _mechanism, callback):
        callback(None)
        if self.provider.smtp_auth_fail_once:
            self.provider.smtp_auth_fail_once = False
            raise smtplib.SMTPAuthenticationError(535, b"expired token")
        return 235, b"ok"

    def send_message(self, message, *, from_addr, to_addrs):
        self.provider.smtp_from = str(from_addr)
        self.provider.smtp_calls += 1
        self.provider.smtp_recipients = list(to_addrs)
        if self.provider.smtp_refuse_all_once:
            self.provider.smtp_refuse_all_once = False
            raise smtplib.SMTPRecipientsRefused({str(item): (550, b"refused") for item in to_addrs})
        if self.provider.smtp_refuse_once:
            self.provider.smtp_refuse_once = False
            uid = self.provider.next_uid("Sent")
            self.provider.mailboxes["Sent"][uid] = (
                message.as_bytes(policy=email.policy.SMTP),
                ("\\Seen",),
            )
            return {"recipient@example.test": (550, b"refused")}
        sent_raw = message.as_bytes(policy=email.policy.SMTP)
        if self.provider.smtp_defer_sent:
            self.provider.pending_sent = sent_raw
        else:
            uid = self.provider.next_uid("Sent")
            self.provider.mailboxes["Sent"][uid] = (sent_raw, ("\\Seen",))
        if self.provider.smtp_timeout_once:
            self.provider.smtp_timeout_once = False
            raise TimeoutError("SMTP accepted before timeout")
        return {}

    def quit(self):
        return 221, b"bye"


def _account(
    *,
    alias: str = "gmail",
    copy_preserve_source_fallback: bool = False,
    send_from_addresses: tuple[str, ...] = (),
    auth_kind: str = "password",
) -> AccountConfig:
    return AccountConfig(
        alias=alias,
        address="sender@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        auth_kind=auth_kind,
        credential_record="password:gmail",
        folders=("INBOX", "Archive", "Unrelated"),
        archive_folder="Archive",
        sent_folder="Sent",
        trash_folder="Trash",
        safe_move_folders=("Archive", "Unrelated"),
        copy_preserve_source_fallback=copy_preserve_source_fallback,
        send_from_addresses=send_from_addresses,
    )


def _setup(
    tmp_path: Path,
    *,
    attachment: bool = False,
    account_alias: str = "gmail",
    copy_preserve_source_fallback: bool = False,
    send_from_addresses: tuple[str, ...] = (),
    uidplus: bool = False,
    oauth_access_token: Callable[..., str] | None = None,
):
    provider = FakeMailProvider()
    raw = _raw_message(attachment=attachment)
    provider.mailboxes["INBOX"][7] = (raw, ())
    key = generate_key()
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=key, host_id="host-a"
    )
    credentials.put("password:gmail", {"password": "app-password"})
    writer = ArchiveWriter(tmp_path / "archive", attachment_key=key)
    writer.upsert(parse_message(account=account_alias, folder="INBOX", uid=7, raw=raw, flags=()))
    writer.set_sync_state(account_alias, "INBOX", "777", 7)
    reader = ArchiveReader(tmp_path / "archive", attachment_key=key)
    executor = MailActionExecutor(
        accounts=(
            _account(
                alias=account_alias,
                copy_preserve_source_fallback=copy_preserve_source_fallback,
                send_from_addresses=send_from_addresses,
                auth_kind="password" if oauth_access_token is None else "oauth2",
            ),
        ),
        archive=reader,
        archive_writer=writer,
        credentials=credentials,
        oauth_access_token=oauth_access_token or (lambda _account: "unused"),
        imap_factory=provider.imap,
        smtp_factory=provider.smtp,
        smtp_ssl_factory=provider.smtp,
        uidplus_move_accounts=frozenset({account_alias}) if uidplus else frozenset(),
    )
    context = reader.message_context(
        parse_message(account=account_alias, folder="INBOX", uid=7, raw=raw, flags=()).stable_id
    )
    return provider, executor, reader, context


def _send_payload(context: dict, reader: ArchiveReader, *, with_attachment: bool) -> dict:
    attachments = []
    if with_attachment:
        attachment = reader.list_attachments(str(context["id"]))[0]
        attachments.append(
            {"message_id": str(context["id"]), "attachment_id": attachment["attachment_id"]}
        )
    return {
        "operation": "send",
        "account": str(context["account"]),
        "from": "sender@example.test",
        "to": ["to@example.test"],
        "cc": ["cc@example.test"],
        "bcc": ["hidden@example.test"],
        "subject": "Approved message",
        "body": "Approved body",
        "date": "2026-08-17T12:00:00+00:00",
        "message_id": "<approved@evergarden.example.test>",
        "attachments": attachments,
    }


def test_session_reuses_one_connection_per_mailbox_and_replaces_a_dead_one(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(tmp_path)
    opened: list[FakeIMAP] = []

    def counting(*args, **kwargs):
        opened.append(provider.imap(*args, **kwargs))
        return opened[-1]

    executor.connector.imap_factory = counting
    mark = _mark_payload(context)
    with executor.session():
        assert executor.execute(mark, "a" * 64)["status"] == "confirmed"
        assert executor.reconcile(mark, "a" * 64)["reconciled"] is True
        # A refused identity check keeps the stream in step, so the connection stays.
        with pytest.raises(ProviderDefinitelyRejected, match="UIDVALIDITY"):
            executor.execute({**mark, "source_uid_validity": "999"}, "b" * 64)
        assert len(opened) == 1 and not opened[0].logged_out
        opened[0].dead = True
        executor.reconcile(mark, "a" * 64)
        assert len(opened) == 2 and opened[0].logged_out
    assert all(client.logged_out for client in opened)
    # Outside a session every action opens and closes its own connection.
    executor.reconcile(mark, "a" * 64)
    assert len(opened) == 3 and opened[2].logged_out


def test_live_sent_metadata_is_bounded_header_only_and_read_only(tmp_path: Path) -> None:
    provider, executor, _reader, _context = _setup(tmp_path)
    provider.mailboxes["Sent"][3] = (
        _raw_message(message_id="<sent@example.test>", subject="Bearer abcdefghijklmnop"),
        ("\\Seen",),
    )
    rows = executor.list_sent_metadata(
        "gmail",
        since=dt.datetime(2026, 8, 16, tzinfo=dt.UTC),
        before=dt.datetime(2026, 8, 18, tzinfo=dt.UTC),
        limit=10,
    )
    assert len(rows) == 1
    assert rows[0]["account"] == "gmail"
    assert rows[0]["folder"] == "Sent"
    assert rows[0]["subject"] != "Bearer abcdefghijklmnop"
    assert "[REDACTED]" in rows[0]["subject"]
    assert rows[0]["flags"] == ["\\Seen"]
    assert provider.move_calls == 0
    assert provider.copy_calls == 0
    assert provider.store_calls == 0
    assert provider.smtp_calls == 0
    assert ("select", "Sent", True) in provider.imap_calls
    fetch = next(call for call in provider.imap_calls if call[:2] == ("uid", "FETCH"))
    assert "BODY.PEEK[HEADER.FIELDS" in str(fetch[-1])
    assert "BODY.PEEK[]" not in str(fetch[-1])


def test_live_sent_metadata_rejects_invalid_bounds_and_provider_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider, executor, _reader, _context = _setup(tmp_path)
    aware = dt.datetime(2026, 8, 17, tzinfo=dt.UTC)
    with pytest.raises(ProviderDefinitelyRejected, match="time window"):
        executor.list_sent_metadata("gmail", since=aware, before=aware, limit=10)
    with pytest.raises(ProviderDefinitelyRejected, match="limit"):
        executor.list_sent_metadata(
            "gmail", since=aware, before=aware + dt.timedelta(days=1), limit=0
        )

    original_uid = FakeIMAP.uid

    def reject_search(self, command, *args):
        if command.upper() == "SEARCH":
            return "NO", []
        return original_uid(self, command, *args)

    monkeypatch.setattr(FakeIMAP, "uid", reject_search)
    with pytest.raises(ProviderDefinitelyRejected, match="search"):
        executor.list_sent_metadata(
            "gmail", since=aware, before=aware + dt.timedelta(days=1), limit=10
        )
    assert provider.smtp_calls == 0


def test_live_sent_metadata_skips_missing_and_invalid_dated_headers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider, executor, _reader, _context = _setup(tmp_path)
    for uid in range(1, 5):
        provider.mailboxes["Sent"][uid] = (
            _raw_message(message_id=f"<sent-{uid}@example.test>"),
            (),
        )
    original_parse = parse_message
    dates = {
        1: "malformed",
        2: "2026-08-17T10:00:00",
        3: "2026-08-20T10:00:00+00:00",
        4: "2026-08-17T10:00:00+00:00",
    }

    def dated_parse(**kwargs):
        return dataclasses.replace(original_parse(**kwargs), date_received=dates[kwargs["uid"]])

    monkeypatch.setattr("evergarden.mail.actions.parse_message", dated_parse)
    rows = executor.list_sent_metadata(
        "gmail",
        since=dt.datetime(2026, 8, 16, tzinfo=dt.UTC),
        before=dt.datetime(2026, 8, 18, tzinfo=dt.UTC),
        limit=10,
    )
    assert [row["date_received"] for row in rows] == ["2026-08-17T10:00:00+00:00"]

    monkeypatch.setattr(
        MailActionExecutor,
        "_fetch_sent_header",
        staticmethod(lambda _client, _uid: None),
    )
    assert (
        executor.list_sent_metadata(
            "gmail",
            since=dt.datetime(2026, 8, 16, tzinfo=dt.UTC),
            before=dt.datetime(2026, 8, 18, tzinfo=dt.UTC),
            limit=10,
        )
        == []
    )


def test_sent_header_fetch_rejects_malformed_provider_results() -> None:
    class Client:
        def __init__(self, status, values):
            self.status = status
            self.values = values

        def uid(self, *_args):
            return self.status, self.values

    with pytest.raises(ProviderDefinitelyRejected, match="fetch was rejected"):
        MailActionExecutor._fetch_sent_header(Client("NO", []), 7)
    assert MailActionExecutor._fetch_sent_header(Client("OK", [b")"]), 7) is None
    with pytest.raises(ProviderDefinitelyRejected, match="different UID"):
        MailActionExecutor._fetch_sent_header(
            Client("OK", [(b"1 (UID 8 RFC822.SIZE 10)", b"headers")]), 7
        )
    with pytest.raises(ProviderDefinitelyRejected, match=r"omitted RFC822\.SIZE"):
        MailActionExecutor._fetch_sent_header(Client("OK", [("1 (UID 7 FLAGS ())", b"headers")]), 7)


def test_mail_runtime_combines_live_sent_metadata_without_partial_fallback() -> None:
    runtime = object.__new__(MailRuntime)
    runtime.accounts = (_account(alias="gmail"), _account(alias="outlook"))

    class Actions:
        def list_sent_metadata(self, alias, **_kwargs):
            return [
                {
                    "account": alias,
                    "date_received": (
                        "2026-08-17T11:00:00+00:00"
                        if alias == "outlook"
                        else "2026-08-17T10:00:00+00:00"
                    ),
                }
            ]

    runtime.actions = Actions()
    window = {
        "since": dt.datetime(2026, 8, 16, tzinfo=dt.UTC),
        "before": dt.datetime(2026, 8, 18, tzinfo=dt.UTC),
        "per_account_limit": 10,
    }
    assert [row["account"] for row in runtime.list_sent_metadata(None, **window)] == [
        "outlook",
        "gmail",
    ]
    assert [row["account"] for row in runtime.list_sent_metadata("gmail", **window)] == ["gmail"]
    with pytest.raises(ValueError, match="unknown"):
        runtime.list_sent_metadata("missing", **window)


def _move_payload(
    context: dict,
    *,
    destination: str = "Archive",
    copy_preserve_source_fallback: bool = False,
) -> dict:
    return {
        "operation": "archive" if destination == "Archive" else "move",
        "account": str(context["account"]),
        "stable_message_id": str(context["id"]),
        "source_folder": "INBOX",
        "source_uid": 7,
        "source_uid_validity": "777",
        "provider_message_id": str(context["message_id"]),
        "raw_body_sha256": str(context["raw_body_sha256"]),
        "destination": destination,
        "copy_preserve_source_fallback": copy_preserve_source_fallback,
    }


def _mark_payload(context: dict) -> dict:
    return {
        "operation": "mark",
        "account": str(context["account"]),
        "stable_message_id": str(context["id"]),
        "source_folder": "INBOX",
        "source_uid": 7,
        "source_uid_validity": "777",
        "provider_message_id": str(context["message_id"]),
        "raw_body_sha256": str(context["raw_body_sha256"]),
        "action": "seen",
    }


def _lease() -> LeaseToken:
    return LeaseToken("approved-mail-action", "approval", "host-a", 1, "nonce")


def _fence(*, trash: bool = False) -> SideEffectFence:
    return SideEffectFence(
        FenceConfig(
            "host-a",
            "host-a",
            1,
            True,
            trash_actions_enabled=trash,
        )
    )


_PROVIDER_MUTATIONS = frozenset({"MOVE", "COPY", "STORE", "EXPUNGE"})


def _uidplus_payload(context: dict, operation: str = "archive") -> dict:
    destination = "Trash" if operation == "trash" else "Archive"
    return {
        **_move_payload(context, destination=destination),
        "operation": operation,
        "uidplus_move_fallback": True,
    }


def _mutations(provider: FakeMailProvider) -> list[tuple[str, str]]:
    """Return every mutating UID command the provider received, in order."""
    return [
        (call[1], call[2])
        for call in provider.imap_calls
        if call[0] == "uid" and call[1] in _PROVIDER_MUTATIONS
    ]


def _approval_service(
    account: AccountConfig, *, uidplus: bool = False, repository: ApprovalRepository | None = None
) -> ApprovalService:
    return ApprovalService(
        repository or ApprovalRepository(),
        accounts=(account,),
        uidplus_move_accounts=frozenset({account.alias}) if uidplus else frozenset(),
    )


def _human_approved(service: ApprovalService, payload: dict):
    draft = service.prepare(
        kind=IntentKind(str(payload["operation"])),
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )
    return draft, approval


def _run_approved(service: ApprovalService, draft, approval, payload: dict, executor) -> dict:
    return service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(trash=draft.kind is IntentKind.TRASH),
        lease=_lease(),
        executor=executor,
    )


def test_send_preserves_bcc_envelope_attachment_message_id_and_sent_copy(tmp_path: Path) -> None:
    provider, executor, reader, context = _setup(tmp_path, attachment=True)
    payload = _send_payload(context, reader, with_attachment=True)
    first_mime, _ = executor._build_message(payload)
    second_mime, _ = executor._build_message(payload)
    assert first_mime.as_bytes(policy=email.policy.SMTP) == second_mime.as_bytes(
        policy=email.policy.SMTP
    )

    first = executor.execute(payload, "k" * 64)
    assert first["sent_copy_verified"] is True
    assert provider.smtp_calls == 1
    assert provider.smtp_from == "sender@example.test"
    assert provider.smtp_recipients == [
        "to@example.test",
        "cc@example.test",
        "hidden@example.test",
    ]
    sent_raw = provider.mailboxes["Sent"][1][0]
    sent = email.message_from_bytes(sent_raw, policy=email.policy.default)
    assert sent.get("Bcc") is None
    assert sent["Message-ID"] == "<approved@evergarden.example.test>"
    assert len(list(sent.iter_attachments())) == 1
    assert (
        reader.search("Approved", account="gmail", folder="Sent")[0]["subject"]
        == "Approved message"
    )

    replay = executor.execute(payload, "k" * 64)
    assert replay["already_applied"] is True
    assert provider.smtp_calls == 1


def test_send_accepts_only_allowlisted_visible_from_and_uses_it_as_envelope(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(
        tmp_path,
        send_from_addresses=("public-name@example.test", "sender@example.test"),
    )
    payload = {
        **_send_payload(context, reader, with_attachment=False),
        "from": "public-name@example.test",
    }
    result = executor.execute(payload, "v" * 64)
    assert result["status"] == "confirmed"
    assert provider.smtp_login_address == "sender@example.test"
    assert provider.smtp_from == "public-name@example.test"
    sent = email.message_from_bytes(provider.mailboxes["Sent"][1][0], policy=email.policy.default)
    assert sent["From"] == "public-name@example.test"

    with pytest.raises(ProviderDefinitelyRejected, match="not allowlisted"):
        executor.execute({**payload, "from": "spoof@example.test"}, "w" * 64)


def test_send_uses_encrypted_staged_attachment_and_consumes_it_after_smtp(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    staged = StagedAttachmentStore(executor.credentials)
    executor.staged_attachments = staged
    staged_value = staged.stage(
        filename="local.txt",
        mimetype="text/plain",
        content_base64=base64.b64encode(b"local attachment").decode(),
    )
    reference = {
        key: staged_value[key]
        for key in ("staged_attachment_id", "filename", "mimetype", "size", "sha256")
    }
    payload = {
        **_send_payload(context, reader, with_attachment=False),
        "attachments": [reference],
    }
    result = executor.execute(payload, "s" * 64)
    assert result["status"] == "confirmed"
    sent = email.message_from_bytes(provider.mailboxes["Sent"][1][0], policy=email.policy.default)
    attachment = next(iter(sent.iter_attachments()))
    assert attachment.get_filename() == "local.txt"
    assert attachment.get_payload(decode=True) == b"local attachment"
    with pytest.raises(StagedAttachmentError, match="expired or consumed"):
        staged.describe(staged_value["staged_attachment_id"])


def test_smtp_external_success_timeout_reconciles_without_resend(tmp_path: Path) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    provider.smtp_timeout_once = True
    payload = _send_payload(context, reader, with_attachment=False)
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.SEND,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    with pytest.raises(ProviderOutcomeUnknown, match="SMTP"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    recovered = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert recovered["state"] == "CONFIRMED"
    assert recovered["reconciled"] is True
    assert provider.smtp_calls == 1


def test_confirmed_send_refreshes_delayed_sent_copy_without_resend(tmp_path: Path) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    provider.smtp_defer_sent = True
    provider.append_defer_visibility = True
    payload = _send_payload(context, reader, with_attachment=False)
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.SEND,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    first = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert first["state"] == "CONFIRMED"
    assert first["sent_copy_verified"] is False
    still_pending = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert still_pending["sent_copy_verified"] is False
    assert provider.smtp_calls == 1
    assert provider.append_calls == 1

    assert provider.pending_sent is not None
    provider.mailboxes["Sent"][1] = (provider.pending_sent, ("\\Seen",))
    verified = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert verified["sent_copy_verified"] is True
    assert verified["reconciled"] is True
    assert provider.smtp_calls == 1
    assert provider.append_calls == 1


def test_send_appends_sent_copy_once_when_smtp_does_not_auto_save(tmp_path: Path) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    provider.smtp_defer_sent = True
    payload = _send_payload(context, reader, with_attachment=False)

    first = executor.execute(payload, "p" * 64)
    assert first["sent_copy_verified"] is True
    assert first["sent_copy_state"] == "verified"
    assert provider.smtp_calls == 1
    assert provider.append_calls == 1
    replay = executor.execute(payload, "p" * 64)
    assert replay["already_applied"] is True
    assert provider.smtp_calls == 1
    assert provider.append_calls == 1


def test_move_timeout_reconciles_destination_and_updates_archive(tmp_path: Path) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    provider.move_timeout_once = True
    payload = _move_payload(context, destination="Unrelated")
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.MOVE,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    with pytest.raises(ProviderOutcomeUnknown, match="MOVE"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    recovered = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert recovered["destination"] == "Unrelated"
    assert recovered["verified"] is True
    assert provider.move_calls == 1
    assert reader.get_message(str(context["id"]))["folder"] == "Unrelated"


def test_archive_requires_source_absence_even_when_destination_already_has_copy(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    raw = provider.mailboxes["INBOX"][7][0]
    provider.mailboxes["Archive"][20] = (raw, ())
    result = executor.execute(_move_payload(context), "m" * 64)
    assert result["verified"] is True
    assert provider.move_calls == 1
    assert 7 not in provider.mailboxes["INBOX"]
    assert reader.get_message(str(context["id"]))["folder"] == "Archive"


def test_move_rejects_uidvalidity_drift_and_provider_without_native_move(tmp_path: Path) -> None:
    provider, executor, _reader, context = _setup(tmp_path)
    payload = _move_payload(context)
    provider.uid_validity["INBOX"] = "changed"
    with pytest.raises(ProviderDefinitelyRejected, match="UIDVALIDITY"):
        executor.execute(payload, "m" * 64)
    assert provider.move_calls == 0

    provider.uid_validity["INBOX"] = "777"
    provider.supports_move = False
    with pytest.raises(ProviderDefinitelyRejected, match="native"):
        executor.execute(payload, "m" * 64)
    assert provider.move_calls == 0


def test_reversible_trash_requires_separate_fence_and_never_falls_back_to_copy(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    payload = {
        **_move_payload(context, destination="Trash"),
        "operation": "trash",
        "copy_preserve_source_fallback": False,
    }
    service = ApprovalService(ApprovalRepository(), accounts=(_account(),))
    draft = service.prepare(
        kind=IntentKind.TRASH,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("operator", "approval-ui", "approval-ui", True),
    )

    with pytest.raises(FenceRejected, match="Trash actions are disabled"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    assert provider.move_calls == 0
    assert service.repository.approvals[approval.approval_id].consumed_at is None

    result = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(trash=True),
        lease=_lease(),
        executor=executor,
    )
    assert result["operation"] == "trash"
    assert provider.move_calls == 1
    assert provider.copy_calls == 0
    assert provider.store_calls == 0
    assert 7 not in provider.mailboxes["INBOX"]
    assert provider.mailboxes["Trash"]
    assert reader.get_message(str(context["id"]))["folder"] == "Trash"

    provider2, executor2, _reader2, context2 = _setup(tmp_path / "no-move")
    provider2.supports_move = False
    payload2 = {
        **_move_payload(context2, destination="Trash"),
        "operation": "trash",
        "copy_preserve_source_fallback": False,
    }
    with pytest.raises(ProviderDefinitelyRejected, match="native IMAP MOVE"):
        executor2.execute(payload2, "t" * 64)
    assert provider2.copy_calls == 0
    assert 7 in provider2.mailboxes["INBOX"]

    with pytest.raises(ApprovalError, match="Trash destination"):
        service.prepare(
            kind=IntentKind.TRASH,
            payload={**payload, "destination": "Archive"},
            actor=Actor("agent", "codex", "mcp", False),
        )


def test_copy_preserve_source_fallback_is_idempotent_and_never_removes_source(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(
        tmp_path,
        account_alias="icloud",
        copy_preserve_source_fallback=True,
    )
    provider.supports_move = False
    payload = _move_payload(context, copy_preserve_source_fallback=True)

    first = executor.execute(payload, "c" * 64)
    assert first["verified"] is True
    assert first["degraded_copy"] is True
    assert first["source_preserved"] is True
    assert first["source_seen"] is True
    assert provider.copy_calls == 1
    assert provider.move_calls == 0
    assert provider.store_calls == 1
    assert 7 in provider.mailboxes["INBOX"]
    assert "\\Seen" in provider.mailboxes["INBOX"][7][1]
    assert len(provider.mailboxes["Archive"]) == 1
    locations = reader.message_locations(str(context["id"]))
    assert {item["folder"] for item in locations} == {"INBOX", "Archive"}
    assert next(item for item in locations if item["folder"] == "INBOX")["flags"] == ["\\Seen"]

    replay = executor.execute(payload, "c" * 64)
    assert replay["already_applied"] is True
    assert provider.copy_calls == 1
    assert provider.store_calls == 1
    assert 7 in provider.mailboxes["INBOX"]


def test_copy_timeout_reconciles_without_second_copy_or_source_removal(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(
        tmp_path,
        account_alias="icloud",
        copy_preserve_source_fallback=True,
    )
    provider.supports_move = False
    provider.copy_timeout_once = True
    payload = _move_payload(context, copy_preserve_source_fallback=True)
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.ARCHIVE,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    with pytest.raises(ProviderOutcomeUnknown, match="COPY"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    recovered = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert recovered["state"] == "CONFIRMED"
    assert recovered["reconciled"] is True
    assert recovered["source_preserved"] is True
    assert recovered["source_seen"] is False
    assert provider.copy_calls == 1
    assert provider.store_calls == 0
    assert provider.move_calls == 0
    assert 7 in provider.mailboxes["INBOX"]
    assert {item["folder"] for item in reader.message_locations(str(context["id"]))} == {
        "INBOX",
        "Archive",
    }


def test_copy_fallback_reuses_existing_copy_and_completes_seen_state(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(
        tmp_path,
        account_alias="icloud",
        copy_preserve_source_fallback=True,
    )
    provider.supports_move = False
    provider.mailboxes["Archive"][20] = provider.mailboxes["INBOX"][7]
    result = executor.execute(_move_payload(context, copy_preserve_source_fallback=True), "e" * 64)
    assert result["already_applied"] is True
    assert result["source_seen"] is True
    assert provider.copy_calls == 0
    assert provider.store_calls == 1
    assert 7 in provider.mailboxes["INBOX"]


def test_readiness_accepts_only_the_account_pinned_copy_fallback(tmp_path: Path) -> None:
    provider, executor, _reader, _context = _setup(
        tmp_path,
        account_alias="icloud",
        copy_preserve_source_fallback=True,
    )
    provider.supports_move = False
    readiness = executor.probe_account("icloud")
    assert readiness == {
        "account": "icloud",
        "imap_authenticated": True,
        "folders_verified": 5,
        "native_move": False,
        "trash_folder_verified": True,
        "reversible_trash_ready": False,
        "permanent_delete_supported": False,
        "copy_preserve_source_fallback": True,
        "organization_ready": True,
        "organization_strategy": "copy_preserve_source",
        "smtp_authenticated": True,
        "smtp_mode": "starttls",
        "provider_mutations": 0,
    }
    assert provider.copy_calls == 0
    assert provider.store_calls == 0
    assert provider.smtp_calls == 0


def test_organization_capability_preflight_has_no_mail_or_smtp_side_effects(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, _context = _setup(
        tmp_path, account_alias="icloud", copy_preserve_source_fallback=True
    )
    provider.supports_move = False
    assert executor.organization_capabilities("icloud") == {
        "account": "icloud",
        "native_move": False,
        "uidplus": True,
        "copy_preserve_source_fallback": True,
        "uidplus_move_fallback": False,
        "provider_mutations": 0,
    }
    assert provider.imap_calls == []
    assert provider.copy_calls == provider.move_calls == provider.store_calls == 0
    assert provider.smtp_calls == provider.append_calls == 0
    assert 7 in provider.mailboxes["INBOX"]
    assert provider.mailboxes["INBOX"][7][1] == ()


def test_icloud_mark_updates_only_the_approved_folder_copy(tmp_path: Path) -> None:
    provider, executor, reader, context = _setup(
        tmp_path,
        account_alias="icloud",
        copy_preserve_source_fallback=True,
    )
    provider.supports_move = False
    executor.execute(
        _move_payload(context, copy_preserve_source_fallback=True),
        "c" * 64,
    )
    result = executor.execute({**_mark_payload(context), "action": "flag"}, "f" * 64)
    assert result["enabled"] is True
    locations = {item["folder"]: item for item in reader.message_locations(str(context["id"]))}
    assert set(locations["INBOX"]["flags"]) == {"\\Seen", "\\Flagged"}
    assert locations["Archive"]["flags"] == []
    assert "\\Flagged" in provider.mailboxes["INBOX"][7][1]
    assert "\\Flagged" not in next(iter(provider.mailboxes["Archive"].values()))[1]


def test_copy_fallback_definite_rejection_and_partial_seen_never_replay(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(
        tmp_path,
        account_alias="icloud",
        copy_preserve_source_fallback=True,
    )
    provider.supports_move = False
    payload = _move_payload(context, copy_preserve_source_fallback=True)
    with pytest.raises(ProviderDefinitelyRejected, match="strategy"):
        executor.execute({**payload, "copy_preserve_source_fallback": False}, "x" * 64)

    provider.copy_reject_once = True
    with pytest.raises(ProviderDefinitelyRejected, match="COPY"):
        executor.execute(payload, "x" * 64)
    assert provider.copy_calls == 0
    assert not provider.mailboxes["Archive"]

    provider.store_timeout_once = True
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.ARCHIVE,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )
    with pytest.raises(ProviderPartialOutcome, match="seen-state"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    with pytest.raises(ApprovalError, match="partial outcome"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    assert provider.copy_calls == 1
    assert provider.store_calls == 1
    assert 7 in provider.mailboxes["INBOX"]


def test_confirmed_copy_with_delayed_visibility_refreshes_read_only(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(
        tmp_path,
        account_alias="icloud",
        copy_preserve_source_fallback=True,
    )
    provider.supports_move = False
    provider.copy_defer_visibility = True
    payload = _move_payload(context, copy_preserve_source_fallback=True)
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.ARCHIVE,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    first = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert first["state"] == "CONFIRMED"
    assert first["verified"] is False
    still_pending = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert still_pending["verified"] is False
    assert provider.copy_calls == 1
    assert provider.store_calls == 1

    assert provider.pending_copy is not None
    destination, uid, raw, flags = provider.pending_copy
    provider.mailboxes[destination][uid] = (raw, flags)
    refreshed = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert refreshed["verified"] is True
    assert refreshed["reconciled"] is True
    assert refreshed["source_preserved"] is True
    assert provider.copy_calls == 1
    assert provider.store_calls == 1


def test_mark_external_success_timeout_reconciles_flags_without_second_store(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    provider.store_timeout_once = True
    payload = _mark_payload(context)
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.MARK,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )
    with pytest.raises(ProviderOutcomeUnknown, match="flag"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    recovered = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert recovered["enabled"] is True
    assert recovered["verified"] is True
    assert provider.store_calls == 1
    assert "\\Seen" in reader.get_message(str(context["id"]))["flags"]


def test_unknown_reconciliation_never_blindly_replays_and_endpoint_kind_is_bound(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    payload = _send_payload(context, reader, with_attachment=False)
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.SEND,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )
    provider.smtp_timeout_once = True
    with pytest.raises(ApprovalError, match="endpoint"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
            expected_kind=IntentKind.MOVE,
        )
    with pytest.raises(ProviderOutcomeUnknown):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    provider.mailboxes["Sent"].clear()
    with pytest.raises(ApprovalError, match="not replayed"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    assert provider.smtp_calls == 1
    assert "Approved body" not in repr(service.repository.executions)


def test_oauth_ssl_send_and_reversible_mark_paths_are_exercised(tmp_path: Path) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    oauth_account = AccountConfig(
        alias="oauth",
        address="sender@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        smtp_port=465,
        smtp_mode="ssl",
        auth_kind="oauth2",
        credential_record="oauth:test",
        folders=("INBOX", "Archive"),
        archive_folder="Archive",
        sent_folder="Sent",
        safe_move_folders=("Archive",),
    )
    oauth_tokens: list[str] = []

    def oauth(_account: AccountConfig) -> str:
        oauth_tokens.append("requested")
        return "access-token"

    oauth_executor = MailActionExecutor(
        accounts=(oauth_account,),
        archive=reader,
        archive_writer=executor.archive_writer,
        credentials=executor.credentials,
        oauth_access_token=oauth,
        imap_factory=provider.imap,
        smtp_factory=provider.smtp,
        smtp_ssl_factory=provider.smtp,
    )
    payload = _send_payload(context, reader, with_attachment=False)
    payload["account"] = "oauth"
    result = oauth_executor.execute(payload, "o" * 64)
    assert result["sent_copy_verified"] is True
    assert oauth_tokens == ["requested", "requested", "requested"]

    mark = _mark_payload(context)
    first = executor.execute(mark, "f" * 64)
    assert first["enabled"] is True
    assert first["reconciled"] is False
    replay = executor.execute(mark, "f" * 64)
    assert replay["already_applied"] is True
    unseen = {**mark, "action": "unseen"}
    removed = executor.execute(unseen, "u" * 64)
    assert removed["enabled"] is False
    assert provider.store_calls == 2

    readiness = executor.probe_account("gmail")
    assert readiness == {
        "account": "gmail",
        "imap_authenticated": True,
        "folders_verified": 5,
        "native_move": True,
        "trash_folder_verified": True,
        "reversible_trash_ready": True,
        "permanent_delete_supported": False,
        "copy_preserve_source_fallback": False,
        "organization_ready": True,
        "organization_strategy": "native_move",
        "smtp_authenticated": True,
        "smtp_mode": "starttls",
        "provider_mutations": 0,
    }
    assert provider.smtp_calls == 1


def test_oauth_authentication_rejection_forces_one_refresh_before_write(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    del executor
    account = AccountConfig(
        alias="oauth",
        address="sender@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        auth_kind="oauth2",
        credential_record="oauth:test",
        folders=("INBOX", "Archive"),
        archive_folder="Archive",
        sent_folder="Sent",
        safe_move_folders=("Archive",),
    )
    requests: list[bool] = []

    def oauth(_account: AccountConfig, *, force_refresh: bool = False) -> str:
        requests.append(force_refresh)
        return "refreshed" if force_refresh else "cached"

    action = MailActionExecutor(
        accounts=(account,),
        archive=reader,
        archive_writer=ArchiveWriter(tmp_path / "archive"),
        credentials=CredentialStore(
            tmp_path / "unused" / "credentials.db", key=generate_key(), host_id="host-a"
        ),
        oauth_access_token=oauth,
        imap_factory=provider.imap,
        smtp_factory=provider.smtp,
        smtp_ssl_factory=provider.smtp,
    )
    provider.imap_auth_fail_once = True
    provider.smtp_auth_fail_once = True
    payload = _send_payload(context, reader, with_attachment=False)
    payload["account"] = "oauth"
    result = action.execute(payload, "a" * 64)
    assert result["sent_copy_verified"] is True
    assert requests == [False, True, False, True, False]
    assert provider.smtp_calls == 1


def test_imap_authentication_retries_transient_exchange_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _provider, executor, _reader, _context = _setup(tmp_path)
    account = AccountConfig(
        alias="oauth", address="user@example.test", imap_host="imap.test", auth_kind="oauth2"
    )
    calls: list[bool] = []
    sleeps: list[float] = []
    client = object()

    def authenticate_once(_account, *, force_refresh):
        calls.append(force_refresh)
        if len(calls) == 1:
            raise imaplib.IMAP4.error("User is authenticated but not connected.")
        return client

    monkeypatch.setattr(executor.connector, "authenticate_once", authenticate_once)
    monkeypatch.setattr("evergarden.mail.imap_connector.time.sleep", sleeps.append)
    assert executor._authenticate_imap(account) is client
    assert calls == [False, False]
    assert sleeps == [1]

    calls.clear()

    def always_rejected(_account, *, force_refresh):
        calls.append(force_refresh)
        raise imaplib.IMAP4.error("User is authenticated but not connected.")

    monkeypatch.setattr(executor.connector, "authenticate_once", always_rejected)
    with pytest.raises(imaplib.IMAP4.error, match="not connected"):
        executor._authenticate_imap(account)
    assert calls == [False] * 12


def test_provider_executor_fails_closed_on_malformed_or_unprovable_requests(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    send = _send_payload(context, reader, with_attachment=False)
    with pytest.raises(ProviderDefinitelyRejected, match="unsupported"):
        executor.execute({"operation": "unsupported"}, "x" * 64)
    with pytest.raises(ProviderDefinitelyRejected, match="unsupported"):
        executor.reconcile({"operation": "unsupported"}, "x" * 64)
    with pytest.raises(ProviderDefinitelyRejected, match="unknown"):
        executor.execute({**send, "account": "missing"}, "x" * 64)
    with pytest.raises(ProviderDefinitelyRejected, match="From"):
        executor.execute({**send, "from": "spoof@example.test"}, "x" * 64)
    with pytest.raises(ProviderDefinitelyRejected, match="preflight"):
        executor.execute({**send, "message_id": "bad\nvalue"}, "x" * 64)
    with pytest.raises(ProviderDefinitelyRejected, match="recipient"):
        executor.execute({**send, "bcc": ["hidden@example.test\r\nBcc: x@y.test"]}, "x" * 64)

    move = _move_payload(context)
    with pytest.raises(ProviderDefinitelyRejected, match="allowlisted"):
        executor.execute({**move, "destination": "NeverAllowed"}, "x" * 64)
    with pytest.raises(ProviderDefinitelyRejected, match="mark action"):
        executor.execute({**_mark_payload(context), "action": "deleted"}, "x" * 64)

    provider.mailboxes["INBOX"].clear()
    with pytest.raises(ProviderSourceGone, match="gone"):
        executor.execute(move, "x" * 64)


def test_receive_only_account_blocks_prepare_and_execute_without_consuming_approval(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    payload = _send_payload(context, reader, with_attachment=False)
    repository = ApprovalRepository()
    unrestricted = ApprovalService(repository)
    draft = unrestricted.prepare(
        kind=IntentKind.SEND, payload=payload, actor=Actor("agent", "codex", "mcp", False)
    )
    approval = unrestricted.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    # The account became receive-only after the durable approval was issued,
    # e.g. a Thunderbird bridge account gained native sync.
    restricted = ApprovalService(
        repository, receive_only_accounts=frozenset({str(payload["account"])})
    )
    with pytest.raises(ApprovalError, match="receiving and notifications only"):
        restricted.prepare(
            kind=IntentKind.SEND, payload=payload, actor=Actor("agent", "codex", "mcp", False)
        )
    with pytest.raises(ApprovalError, match="receiving and notifications only"):
        restricted.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    assert provider.smtp_calls == 0

    # The rejection happens before the execution claim, so lifting the
    # restriction leaves the durable approval executable, not burned.
    unrestricted.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=_fence(),
        lease=_lease(),
        executor=executor,
    )
    assert provider.smtp_calls == 1


def test_smtp_partial_refusal_is_unknown_all_refused_is_definite_and_duplicates_ambiguous(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    payload = _send_payload(context, reader, with_attachment=False)
    provider.smtp_refuse_once = True
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.SEND,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )
    with pytest.raises(ProviderPartialOutcome, match="partial"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    with pytest.raises(ApprovalError, match="partial outcome"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=_fence(),
            lease=_lease(),
            executor=executor,
        )
    assert provider.smtp_calls == 1

    provider.mailboxes["Sent"].clear()
    provider.smtp_refuse_all_once = True
    with pytest.raises(ProviderDefinitelyRejected, match="definitely"):
        executor.execute(payload, "s" * 64)

    sent_raw = _raw_message(message_id=str(payload["message_id"]))
    provider.mailboxes["Sent"][1] = (sent_raw, ("\\Seen",))
    provider.mailboxes["Sent"][2] = (sent_raw, ("\\Seen",))
    with pytest.raises(ProviderOutcomeUnknown, match="ambiguous"):
        executor.reconcile(payload, "r" * 64)

    # The source is untouched and an indexed Message-ID search finds no
    # destination copy: provably not applied.
    with pytest.raises(ProviderProvedNotApplied, match="source still holds"):
        executor.reconcile(_move_payload(context), "r" * 64)
    payload_without_header_id = {
        **_move_payload(context),
        "provider_message_id": "",
    }
    # Without a Message-ID only a body-hash scan remains, which a re-encoded
    # copy would fail: the outcome stays unknown and is never replayed.
    assert executor.reconcile(payload_without_header_id, "r" * 64) is None
    provider.mailboxes["INBOX"].clear()
    with pytest.raises(ProviderSourceGone, match="gone"):
        executor.reconcile(payload_without_header_id, "r" * 64)


def test_authentication_failure_is_not_attempted_before_a_mailbox_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider, executor, _reader, context = _setup(tmp_path)

    def rejected(_account):
        raise imaplib.IMAP4.error("User is authenticated but not connected.")

    monkeypatch.setattr(executor, "_authenticate_imap", rejected)
    with pytest.raises(ProviderNotAttempted, match="before any mailbox operation"):
        executor.execute(_move_payload(context), "test-auth-failure")
    with pytest.raises(ProviderNotAttempted, match="before any mailbox operation"):
        executor.execute(
            {**_move_payload(context), "operation": "mark", "action": "seen"}, "test-auth-failure"
        )
    assert provider.move_calls == provider.copy_calls == provider.store_calls == 0


@pytest.mark.parametrize("operation", ["archive", "trash"])
def test_uidplus_move_copies_verifies_and_expunges_only_the_approved_uid(
    tmp_path: Path, operation: str
) -> None:
    provider, executor, reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    source_raw = provider.mailboxes["INBOX"][7][0]
    bystander = (_raw_message(message_id="<bystander@example.test>"), ("\\Deleted",))
    provider.mailboxes["INBOX"][3] = bystander
    payload = _uidplus_payload(context, operation)
    service = _approval_service(_account(alias="icloud"), uidplus=True)
    draft, approval = _human_approved(service, payload)

    result = _run_approved(service, draft, approval, payload, executor)

    destination = str(payload["destination"])
    assert result["state"] == "CONFIRMED"
    assert result["strategy"] == "uidplus_expunge"
    assert result["verified"] is True
    assert "already_applied" not in result
    assert _mutations(provider) == [("COPY", "7"), ("STORE", "7"), ("EXPUNGE", "7")]
    assert ("uid", "STORE", "7", "+FLAGS.SILENT", "(\\Deleted)") in provider.imap_calls
    # UID EXPUNGE leaves an unrelated message that also carries \Deleted.
    assert provider.mailboxes["INBOX"] == {3: bystander}
    assert list(provider.mailboxes[destination].values()) == [(source_raw, ())]
    assert result["destination_uid"] == next(iter(provider.mailboxes[destination]))
    assert reader.get_message(str(context["id"]))["folder"] == destination


def test_uidplus_move_reuses_an_existing_destination_copy_and_still_removes_the_source(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    provider.mailboxes["Archive"][20] = provider.mailboxes["INBOX"][7]

    result = executor.execute(_uidplus_payload(context), "e" * 64)

    assert result["verified"] is True
    assert result["destination_uid"] == 20
    assert "already_applied" not in result
    assert _mutations(provider) == [("STORE", "7"), ("EXPUNGE", "7")]
    assert 7 not in provider.mailboxes["INBOX"]
    assert list(provider.mailboxes["Archive"]) == [20]


def test_uidplus_move_keeps_the_source_when_the_destination_copy_is_unverified(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    provider.copy_defer_visibility = True
    payload = _uidplus_payload(context)
    service = _approval_service(_account(alias="icloud"), uidplus=True)
    draft, approval = _human_approved(service, payload)

    with pytest.raises(ProviderOutcomeUnknown, match="the source was kept"):
        _run_approved(service, draft, approval, payload, executor)
    assert service.repository.executions[approval.approval_id].state is ExecutionState.UNKNOWN
    assert _mutations(provider) == [("COPY", "7")]
    assert provider.mailboxes["INBOX"][7][1] == ()

    # Reconciliation is read-only: a now-visible copy with the source still
    # present stays unknown and never triggers the deletion.
    assert provider.pending_copy is not None
    folder, uid, raw, flags = provider.pending_copy
    provider.mailboxes[folder][uid] = (raw, flags)
    with pytest.raises(ApprovalError, match="remains unknown"):
        _run_approved(service, draft, approval, payload, executor)
    assert service.repository.executions[approval.approval_id].state is ExecutionState.UNKNOWN
    assert _mutations(provider) == [("COPY", "7")]
    assert 7 in provider.mailboxes["INBOX"]


def test_uidplus_rejected_expunge_is_a_partial_outcome_and_never_replayed(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    provider.expunge_reject_once = True
    payload = _uidplus_payload(context)
    service = _approval_service(_account(alias="icloud"), uidplus=True)
    draft, approval = _human_approved(service, payload)

    with pytest.raises(ProviderPartialOutcome, match="UID EXPUNGE was rejected"):
        _run_approved(service, draft, approval, payload, executor)
    with pytest.raises(ApprovalError, match="partial outcome"):
        _run_approved(service, draft, approval, payload, executor)

    execution = service.repository.executions[approval.approval_id]
    assert execution.state is ExecutionState.UNKNOWN
    assert execution.error_class == "ProviderPartialOutcome"
    assert _mutations(provider) == [("COPY", "7"), ("STORE", "7"), ("EXPUNGE", "7")]
    assert provider.mailboxes["INBOX"][7][1] == ("\\Deleted",)
    assert len(provider.mailboxes["Archive"]) == 1


def test_uidplus_account_without_move_or_uidplus_fails_without_any_mutation(
    tmp_path: Path,
) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    provider.supports_uidplus = False
    payload = _uidplus_payload(context, "trash")
    service = _approval_service(_account(alias="icloud"), uidplus=True)
    draft, approval = _human_approved(service, payload)

    with pytest.raises(ProviderDefinitelyRejected, match="lacks both IMAP MOVE and UIDPLUS"):
        _run_approved(service, draft, approval, payload, executor)

    assert service.repository.executions[approval.approval_id].state is ExecutionState.FAILED
    assert _mutations(provider) == []
    assert provider.mailboxes["INBOX"][7][1] == ()
    assert provider.mailboxes["Trash"] == {}


def test_uidplus_account_uses_native_move_when_the_server_supports_it(tmp_path: Path) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)

    result = executor.execute(_uidplus_payload(context), "n" * 64)

    assert result["verified"] is True
    assert "strategy" not in result
    assert _mutations(provider) == [("MOVE", "7")]
    assert 7 not in provider.mailboxes["INBOX"]


def test_uidplus_copy_is_verified_without_a_provider_message_id_index(tmp_path: Path) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    provider.header_search_unindexed = True
    for uid in (1, 2, 3):
        provider.mailboxes["Archive"][uid] = (
            _raw_message(message_id=f"<older-{uid}@example.test>"),
            (),
        )
    payload = _uidplus_payload(context)

    result = executor.execute(payload, "i" * 64)
    assert result["verified"] is True
    assert result["destination_uid"] == 4
    assert _mutations(provider) == [("COPY", "7"), ("STORE", "7"), ("EXPUNGE", "7")]

    reconciled = executor.reconcile(payload, "i" * 64)
    assert reconciled is not None
    assert reconciled["verified"] is True
    assert reconciled["destination_uid"] == 4
    assert len(_mutations(provider)) == 3


def test_reconcile_does_not_prove_absence_from_an_unindexed_search(tmp_path: Path) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    provider.header_search_unindexed = True
    raw, _flags = provider.mailboxes["INBOX"][7]
    # The earlier COPY landed, then more mail arrived than the bounded
    # newest-UID fallback inspects; the source was never expunged.
    provider.mailboxes["Archive"][1] = (raw, ())
    for uid in range(2, 27):
        provider.mailboxes["Archive"][uid] = (
            _raw_message(message_id=f"<newer-{uid}@example.test>"),
            (),
        )

    assert executor.reconcile(_uidplus_payload(context), "i" * 64) is None
    assert _mutations(provider) == []


@pytest.mark.parametrize("copy_preserve_source_fallback", [False, True])
def test_reconcile_does_not_prove_absence_when_the_copy_was_reencoded(
    tmp_path: Path, copy_preserve_source_fallback: bool
) -> None:
    provider, executor, _reader, context = _setup(
        tmp_path, copy_preserve_source_fallback=copy_preserve_source_fallback
    )
    raw, _flags = provider.mailboxes["INBOX"][7]
    # Exchange and Outlook.com regenerate a moved message's MIME body.
    provider.mailboxes["Archive"][1] = (
        raw.replace(b"Provider identity body", b"Provider regenerated body"),
        (),
    )
    payload = _move_payload(context, copy_preserve_source_fallback=copy_preserve_source_fallback)
    assert payload.get("provider_message_id")

    result = executor.reconcile(payload, "r" * 64)
    if copy_preserve_source_fallback:
        # Same Message-ID and stable id: the re-encoded copy is the approved one.
        assert result is not None and result["destination_uid"] == 1
    else:
        # The source is still present, so a move is not proven either way.
        assert result is None
    assert _mutations(provider) == []

    # Without a Message-ID the body hash stays the only proof.
    unanchored = {**payload, "provider_message_id": ""}
    assert executor.reconcile(unanchored, "r" * 64) is None
    assert _mutations(provider) == []


def test_reconcile_requires_the_source_search_to_prove_the_index(tmp_path: Path) -> None:
    provider, executor, _reader, context = _setup(tmp_path)
    payload = _move_payload(context)
    with pytest.raises(ProviderProvedNotApplied):
        executor.reconcile(payload, "r" * 64)

    # A Message-ID search that cannot even find the source proves nothing.
    provider.header_search_unindexed = True
    assert executor.reconcile(payload, "r" * 64) is None
    provider.header_search_unindexed = False
    # The source is still present but under a new UIDVALIDITY epoch, so the
    # approved UID no longer identifies it: the outcome stays unknown.
    provider.uid_validity["INBOX"] = "778"
    assert executor.reconcile(payload, "r" * 64) is None
    assert _mutations(provider) == []


def test_reconcile_honours_the_declared_copy_strategy_after_the_account_switches(
    tmp_path: Path,
) -> None:
    provider, executor, reader, context = _setup(
        tmp_path, account_alias="icloud", copy_preserve_source_fallback=True
    )
    provider.supports_move = False
    provider.copy_timeout_once = True
    payload = _move_payload(context, copy_preserve_source_fallback=True)
    service = _approval_service(_account(alias="icloud", copy_preserve_source_fallback=True))
    draft, approval = _human_approved(service, payload)
    with pytest.raises(ProviderOutcomeUnknown, match="COPY"):
        _run_approved(service, draft, approval, payload, executor)

    switched = MailActionExecutor(
        accounts=(_account(alias="icloud"),),
        archive=reader,
        archive_writer=executor.archive_writer,
        credentials=executor.credentials,
        oauth_access_token=executor.oauth_access_token,
        imap_factory=provider.imap,
        smtp_factory=provider.smtp,
        smtp_ssl_factory=provider.smtp,
        uidplus_move_accounts=frozenset({"icloud"}),
    )
    with pytest.raises(ProviderDefinitelyRejected, match="strategy"):
        switched.execute(payload, "s" * 64)
    switched_service = _approval_service(
        _account(alias="icloud"), uidplus=True, repository=service.repository
    )

    recovered = _run_approved(switched_service, draft, approval, payload, switched)

    assert recovered["state"] == "CONFIRMED"
    assert recovered["reconciled"] is True
    assert recovered["source_preserved"] is True
    assert _mutations(provider) == [("COPY", "7")]
    assert 7 in provider.mailboxes["INBOX"]


@pytest.mark.parametrize("operation", ["archive", "mark"])
@pytest.mark.parametrize("failure", ["oauth_token", "fetch_oserror"])
def test_pre_mutation_provider_failure_keeps_the_approval_retryable(
    tmp_path: Path, failure: str, operation: str
) -> None:
    token_failures = (
        [OAuthTokenRequestError(503, "temporarily_unavailable", [])]
        if failure == "oauth_token"
        else []
    )

    def access_token(_account: AccountConfig, *, force_refresh: bool = False) -> str:
        if token_failures:
            raise token_failures.pop()
        return "access-token"

    provider, executor, _reader, context = _setup(tmp_path, oauth_access_token=access_token)
    if failure == "fetch_oserror":
        provider.fetch_error_once = ConnectionResetError("connection reset by peer")
    payload = _move_payload(context) if operation == "archive" else _mark_payload(context)
    service = _approval_service(_account(auth_kind="oauth2"))
    draft, approval = _human_approved(service, payload)

    with pytest.raises(ProviderNotAttempted):
        _run_approved(service, draft, approval, payload, executor)
    execution = service.repository.executions[approval.approval_id]
    assert execution.state is ExecutionState.RETRYABLE
    assert execution.error_class == "ProviderNotAttempted"
    assert _mutations(provider) == []

    recovered = _run_approved(service, draft, approval, payload, executor)
    assert recovered["state"] == "CONFIRMED"
    assert service.repository.executions[approval.approval_id].attempt == 2
    assert [command for command, _uid in _mutations(provider)] == (
        ["MOVE"] if operation == "archive" else ["STORE"]
    )


def test_smtp_connection_failure_before_submission_keeps_the_send_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider, executor, reader, context = _setup(tmp_path)
    payload = _send_payload(context, reader, with_attachment=False)
    service = _approval_service(_account())
    draft, approval = _human_approved(service, payload)
    refused = [ConnectionRefusedError("SMTP connection refused")]

    def smtp_factory(*args, **kwargs):
        if refused:
            raise refused.pop()
        return provider.smtp(*args, **kwargs)

    monkeypatch.setattr(executor.smtp_connector, "smtp_factory", smtp_factory)
    with pytest.raises(ProviderNotAttempted, match="before submission"):
        _run_approved(service, draft, approval, payload, executor)
    assert service.repository.executions[approval.approval_id].state is ExecutionState.RETRYABLE
    assert provider.smtp_calls == 0

    recovered = _run_approved(service, draft, approval, payload, executor)
    assert recovered["state"] == "CONFIRMED"
    assert service.repository.executions[approval.approval_id].attempt == 2
    assert provider.smtp_calls == 1


@pytest.mark.parametrize("uidplus", [False, True])
def test_source_identity_change_after_approval_stays_failed(tmp_path: Path, uidplus: bool) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=uidplus)
    provider.supports_move = not uidplus
    payload = _uidplus_payload(context) if uidplus else _move_payload(context)
    service = _approval_service(_account(alias="icloud"), uidplus=uidplus)
    draft, approval = _human_approved(service, payload)
    provider.mailboxes["INBOX"][7] = (
        _raw_message(message_id="<other@example.test>", subject="Replaced after approval"),
        (),
    )

    with pytest.raises(ProviderDefinitelyRejected, match="changed after approval") as raised:
        _run_approved(service, draft, approval, payload, executor)
    assert not isinstance(raised.value, ProviderNotAttempted)
    assert service.repository.executions[approval.approval_id].state is ExecutionState.FAILED
    with pytest.raises(ApprovalError, match="definitely rejected"):
        _run_approved(service, draft, approval, payload, executor)
    assert _mutations(provider) == []


@pytest.mark.parametrize("uidplus", [False, True])
def test_local_archive_failure_after_provider_success_still_confirms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    uidplus: bool,
) -> None:
    provider, executor, _reader, context = _setup(tmp_path, account_alias="icloud", uidplus=uidplus)
    provider.supports_move = not uidplus
    payload = _uidplus_payload(context) if uidplus else _move_payload(context)
    service = _approval_service(_account(alias="icloud"), uidplus=uidplus)
    draft, approval = _human_approved(service, payload)

    def locked(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked at /private/archive.db")

    monkeypatch.setattr(executor.archive_writer, "confirm_move", locked)
    with caplog.at_level(logging.WARNING, logger="evergarden.mail.actions"):
        result = _run_approved(service, draft, approval, payload, executor)

    assert result["state"] == "CONFIRMED"
    assert result["verified"] is True
    assert 7 not in provider.mailboxes["INBOX"]
    assert "local archive update failed" in caplog.text
    assert "error_class=OperationalError" in caplog.text
    assert "/private/archive.db" not in caplog.text


def test_uidplus_capability_preflight_and_readiness_have_no_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider, executor, _reader, _context = _setup(tmp_path, account_alias="icloud", uidplus=True)
    provider.supports_move = False
    assert executor.organization_capabilities("icloud") == {
        "account": "icloud",
        "native_move": False,
        "uidplus": True,
        "copy_preserve_source_fallback": False,
        "uidplus_move_fallback": True,
        "provider_mutations": 0,
    }
    ready = executor.probe_account("icloud")
    assert ready["organization_strategy"] == "uidplus_expunge"
    assert ready["reversible_trash_ready"] is True
    assert ready["organization_ready"] is True

    provider.supports_uidplus = False
    unavailable = executor.probe_account("icloud")
    assert unavailable["organization_strategy"] == "unavailable"
    assert unavailable["reversible_trash_ready"] is False
    assert unavailable["organization_ready"] is False

    def dropped(_self):
        raise OSError("connection reset")

    monkeypatch.setattr(FakeIMAP, "capability", dropped)
    with pytest.raises(ProviderNotAttempted, match="capabilities could not be verified"):
        executor.organization_capabilities("icloud")
    assert _mutations(provider) == []
    assert provider.smtp_calls == provider.append_calls == 0


def test_exchange_rewritten_source_with_same_message_id_still_executes(tmp_path: Path) -> None:
    provider, executor, _reader, context = _setup(tmp_path)
    raw, flags = provider.mailboxes["INBOX"][7]
    provider.mailboxes["INBOX"][7] = (
        raw.replace(b"Provider identity body", b"Provider regenerated body"),
        flags,
    )
    payload = _move_payload(context)
    service = _approval_service(_account())
    draft, approval = _human_approved(service, payload)

    result = _run_approved(service, draft, approval, payload, executor)
    assert result["state"] == "CONFIRMED"
    assert 7 not in provider.mailboxes["INBOX"]

    # Without a Message-ID the body hash remains the only proof of identity.
    provider2, executor2, _reader2, context2 = _setup(tmp_path / "unanchored")
    raw2, flags2 = provider2.mailboxes["INBOX"][7]
    provider2.mailboxes["INBOX"][7] = (raw2.replace(b"identity", b"rewritten"), flags2)
    with pytest.raises(ProviderDefinitelyRejected, match="content changed"):
        executor2.execute({**_move_payload(context2), "provider_message_id": ""}, "u" * 64)
    assert _mutations(provider2) == []


def test_flag_confirms_when_exchange_rewrites_the_message_on_store(tmp_path: Path) -> None:
    provider, executor, _reader, context = _setup(tmp_path)
    provider.rewrite_on_store = True
    payload = {**_mark_payload(context), "action": "flag"}

    result = executor.execute(payload, "f" * 64)
    assert result["enabled"] is True
    assert "\\Flagged" in provider.mailboxes["INBOX"][7][1]
    # The follow-up reconciliation must also accept the rewritten bytes.
    assert executor.reconcile(payload, "f" * 64)["enabled"] is True
