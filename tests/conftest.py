from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from account_fixtures import TEST_ACCOUNTS

from evergarden.approvals.service import ApprovalService
from evergarden.archive.sqlite_archive import ArchiveWriter
from evergarden.mail.models import AttachmentRecord, MessageRecord
from evergarden.mcp.tools import ToolRuntime


@pytest.fixture(autouse=True)
def example_account_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give services built without ``accounts=`` the explicit example inventory.

    The application itself has no built-in inventory (the default is empty);
    tests opt into ``TEST_ACCOUNTS`` here instead of repeating it everywhere.
    """
    for service in (ApprovalService, ToolRuntime):
        monkeypatch.setitem(service.__init__.__kwdefaults__, "accounts", TEST_ACCOUNTS)


def message_record(
    stable_id: str,
    *,
    account: str = "gmail",
    folder: str = "INBOX",
    uid: int = 1,
    subject: str = "Status report",
    body: str = "ordinary body",
    received: str = "2026-08-16T10:00:00+00:00",
    flags: tuple[str, ...] = (),
    attachments: tuple[AttachmentRecord, ...] = (),
) -> MessageRecord:
    return MessageRecord(
        stable_id=stable_id,
        account=account,
        folder=folder,
        uid=uid,
        message_id=f"<{stable_id}@example.test>",
        sender_raw="Alice <alice@example.test>",
        sender_name="Alice",
        sender_email="alice@example.test",
        recipients_to="Eric <eric@example.test>",
        recipients_cc="",
        subject=subject,
        date_received=received,
        body_text=body,
        body_html=f"<p>{body}</p>",
        has_attachments=bool(attachments),
        flags=flags,
        raw_size=len(body),
        raw_body_sha256="f" * 64,
        attachments=attachments,
    )


@pytest.fixture()
def archive_dir(tmp_path: Path) -> Path:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    writer.upsert(
        message_record(
            "a" * 24, attachments=(AttachmentRecord("report.pdf", "application/pdf", 12),)
        )
    )
    writer.upsert(
        message_record(
            "b" * 24,
            account="outlook",
            folder="Inbox",
            uid=2,
            subject="Lunch",
            body="Bearer this-must-never-leak-123456",
            received="2026-08-15T09:00:00+00:00",
            flags=("\\Seen",),
        )
    )
    writer.set_sync_state("gmail", "INBOX", "777", 1)
    writer.set_sync_state("outlook", "Inbox", "888", 2)
    return data


@pytest.fixture()
def fixed_now() -> dt.datetime:
    return dt.datetime(2026, 8, 17, 12, 0, tzinfo=dt.UTC)
