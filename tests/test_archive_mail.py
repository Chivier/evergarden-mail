from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import email
import imaplib
import io
import sqlite3
import ssl
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest
from conftest import message_record

from evergarden.archive.sqlite_archive import (
    ArchiveReader,
    ArchiveWriter,
    ProviderIdentityConflict,
    _dates_are_provider_equivalent,
    _mailboxes_are_provider_equivalent,
    _normalized_reference_ids,
    open_readonly,
    open_writer,
)
from evergarden.auth.credential_store import CredentialStore, generate_key
from evergarden.mail import attachments as attachment_policy
from evergarden.mail.attachments import AttachmentPolicyError, validate_download
from evergarden.mail.inventory import canonical_date
from evergarden.mail.models import AccountConfig, AttachmentRecord, stable_message_id
from evergarden.mail.sync import (
    MailboxSyncIncomplete,
    ReadOnlyMailboxSync,
    _imap_utf7_encode,
    _parse_fetch_flags,
    _quote_folder,
    parse_message,
)


def _raw_message(*, message_id: str = "<mail-1@example.test>", naive_date: bool = False) -> bytes:
    message = EmailMessage()
    message["From"] = "Alice <alice@example.test>"
    message["To"] = "Eric <eric@example.test>"
    message["Subject"] = "Quarterly report"
    message["Message-ID"] = message_id
    message["Date"] = "Sun, 16 Aug 2026 10:00:00" + ("" if naive_date else " +0000")
    message.set_content("Body with Bearer abcdefghijklmnopqrstuvwxyz")
    message.add_alternative("<img src='https://tracker.test/pixel'>", subtype="html")
    message.add_attachment(
        b"%PDF-1.4\npdf-content",
        maintype="application",
        subtype="pdf",
        filename="../report.pdf",
    )
    return message.as_bytes()


def test_stable_ids_and_parser_are_legacy_compatible(tmp_path: Path) -> None:
    with_message_id = stable_message_id(
        account="GMAIL",
        message_id=" <ABC@Example.Test> ",
        sender_email="ignored@example.test",
        date_received="ignored",
        subject="ignored",
        raw_size=10,
    )
    assert with_message_id == stable_message_id(
        account="gmail",
        message_id="abc@example.test",
        sender_email=None,
        date_received=None,
        subject=None,
        raw_size=0,
    )
    fallback = stable_message_id(
        account="gmail",
        message_id="",
        sender_email="ALICE@example.test",
        date_received="2026-08-16T10:00:00+00:00",
        subject=" Report ",
        raw_size=42,
    )
    assert len(fallback) == 24

    parsed = parse_message(
        account="gmail",
        folder="INBOX",
        uid=11,
        raw=_raw_message(naive_date=True),
        flags=("\\Seen",),
    )
    assert parsed.sender_email == "alice@example.test"
    assert parsed.message_id == "mail-1@example.test"
    assert parsed.date_received == "2026-08-16T10:00:00+00:00"
    assert parsed.body_text.startswith("Body with")
    assert "tracker.test" in parsed.body_html
    assert parsed.has_attachments
    assert parsed.attachments == (
        AttachmentRecord("../report.pdf", "application/pdf", len(b"%PDF-1.4\npdf-content")),
    )
    server_sized = parse_message(
        account="gmail",
        folder="INBOX",
        uid=11,
        raw=_raw_message(),
        flags=(),
        raw_size=len(_raw_message()) + 17,
    )
    assert server_sized.raw_size == len(_raw_message()) + 17
    assert canonical_date("malformed-date") == "malformed-date"
    assert canonical_date(None) == ""

    no_id = EmailMessage()
    no_id["From"] = "Alice <alice@example.test>"
    no_id["Subject"] = "No provider identity"
    no_id["Date"] = "Sun, 16 Aug 2026 10:00:00 +0000"
    no_id.set_content("Fallback identity")
    no_id_raw = no_id.as_bytes()
    no_id_small = parse_message(
        account="gmail", folder="INBOX", uid=12, raw=no_id_raw, flags=(), raw_size=100
    )
    no_id_large = parse_message(
        account="gmail", folder="INBOX", uid=12, raw=no_id_raw, flags=(), raw_size=101
    )
    assert no_id_small.stable_id != no_id_large.stable_id
    with pytest.raises(ValueError, match="negative"):
        parse_message(account="gmail", folder="INBOX", uid=12, raw=no_id_raw, flags=(), raw_size=-1)

    html_only = EmailMessage()
    html_only["From"] = "Alice <alice@example.test>"
    html_only["To"] = "Eric <eric@example.test>"
    html_only["Subject"] = "HTML-only action"
    html_only["Bcc"] = "Audit <audit@example.test>"
    html_only["List-ID"] = "Example List <example.test>"
    html_only["Message-ID"] = "<html-only@example.test>"
    html_only["Date"] = "Sun, 16 Aug 2026 10:00:00 +0000"
    html_only.set_content(
        "<style>hidden{}</style><div>Action required<br>Reply now &amp; confirm</div>",
        subtype="html",
    )
    html_parsed = parse_message(
        account="work",
        folder="INBOX",
        uid=12,
        raw=html_only.as_bytes(),
        flags=(),
    )
    assert html_parsed.body_text == "Action required\nReply now & confirm"
    assert "<div>" in html_parsed.body_html
    assert html_parsed.recipients_bcc == "Audit <audit@example.test>"
    assert html_parsed.list_id == "Example List <example.test>"
    html_archive = tmp_path / "html-archive"
    ArchiveWriter(html_archive).upsert(html_parsed, uid_validity="html-uidv")
    with open_readonly(html_archive / "mail-hot.db") as conn:
        stored = conn.execute(
            "SELECT recipients_bcc,list_id FROM messages WHERE id=?",
            (html_parsed.stable_id,),
        ).fetchone()
    assert tuple(stored) == (
        "Audit <audit@example.test>",
        "Example List <example.test>",
    )


def test_archive_migration_repairs_existing_html_only_body(tmp_path: Path) -> None:
    path = tmp_path / "mail-hot.db"
    with open_writer(path) as conn:
        conn.execute(
            "INSERT INTO messages(id,account,body_text,body_html) VALUES (?,?,?,?)",
            (
                "c" * 24,
                "work",
                "",
                "<style>hidden{}</style><div>Action required<br>Reply now &amp; confirm</div>",
            ),
        )
        conn.execute("DELETE FROM archive_schema_migrations WHERE name='003_html_only_body_text'")
        conn.commit()

    with open_writer(path) as conn:
        repaired = conn.execute(
            "SELECT body_text FROM messages WHERE id=?", ("c" * 24,)
        ).fetchone()[0]
        migration = conn.execute(
            "SELECT count(*) FROM archive_schema_migrations WHERE name='003_html_only_body_text'"
        ).fetchone()[0]
    assert repaired == "Action required\nReply now & confirm"
    assert migration == 1


def test_canonical_location_migration_preserves_seeded_active_folder(tmp_path: Path) -> None:
    path = tmp_path / "mail-hot.db"
    record = message_record("c" * 24, account="gmail", folder="Unrelated", uid=30)
    writer = ArchiveWriter(tmp_path)
    writer.upsert(record, uid_validity="unrelated-uidv")
    writer.observe_location(
        dataclasses.replace(record, folder="INBOX", uid=10), uid_validity="inbox-uidv"
    )
    with sqlite3.connect(path) as conn:
        conn.execute(
            "DELETE FROM archive_schema_migrations WHERE name='004_canonical_logical_location'"
        )
        conn.commit()

    with open_writer(path) as conn:
        folder = conn.execute(
            "SELECT folder FROM messages WHERE id=?", (record.stable_id,)
        ).fetchone()[0]
    assert folder == "Unrelated"


def test_hot_location_index_suppresses_stale_shard_only_locations(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    record = message_record(
        "c" * 24,
        account="work",
        folder="Archive",
        uid=30,
        received="2025-01-01T00:00:00+00:00",
    )
    writer.upsert(record, uid_validity="archive-uidv")
    writer.rollover_copy_only(
        scheduled_slot="2026-08-17T04:10:00+01:00", cutoff=dt.date(2026, 8, 10)
    )
    with sqlite3.connect(data / "mail-2025.db") as conn:
        conn.execute(
            "INSERT INTO message_locations(stable_id,account,folder,uid,uid_validity,flags,"
            "raw_body_sha256,active,observed_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                record.stable_id,
                "work",
                "INBOX",
                10,
                "inbox-uidv",
                "[]",
                record.raw_body_sha256,
                1,
                "2026-08-17T00:00:00+00:00",
            ),
        )
        conn.commit()

    assert [item["folder"] for item in ArchiveReader(data).message_locations(record.stable_id)] == [
        "Archive"
    ]


def test_live_index_absence_does_not_resurrect_year_shard_uid(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    record = message_record(
        "d" * 24,
        account="gmail",
        folder="INBOX",
        uid=10,
        received="2025-01-01T00:00:00+00:00",
    )
    writer.upsert(record, uid_validity="old-validity")
    writer.rollover_copy_only(
        scheduled_slot="2026-08-17T04:10:00+01:00", cutoff=dt.date(2026, 8, 10)
    )
    with sqlite3.connect(data / "mail-hot.db") as conn:
        conn.execute("DELETE FROM message_locations WHERE stable_id=?", (record.stable_id,))
        conn.execute("DELETE FROM messages WHERE id=?", (record.stable_id,))
    reader = ArchiveReader(data)
    assert reader.message_locations(record.stable_id)[0]["uid"] == 10
    writer.set_sync_state("gmail", "INBOX", "current-validity", 100)
    assert reader.message_locations(record.stable_id) == []
    assert reader.get_message(record.stable_id)["id"] == record.stable_id


def test_archive_read_search_filters_redaction_and_no_html(
    archive_dir: Path,
) -> None:
    reader = ArchiveReader(archive_dir, max_body_chars=100)
    assert [row["id"] for row in reader.list_recent(unread_only=True)] == ["a" * 24]
    assert (
        reader.list_recent(account="gmail", before="2026-08-17T00:00:00Z")[0]["account"] == "gmail"
    )
    assert reader.list_recent(since="2026-08-16T11:00:00Z") == []
    with pytest.raises(ValueError):
        reader.list_recent(since="not-a-date")

    result = reader.search("ordinary", account="gmail", folder="INBOX")
    assert result[0]["id"] == "a" * 24
    assert reader.search("ordinary", before="2026-08-16T09:00:00Z") == []
    with pytest.raises(ValueError):
        reader.search("")

    redacted = reader.get_message("b" * 24)
    assert "this-must-never-leak" not in redacted["body_text"]
    assert redacted["body_html"] is None
    metadata_only = reader.get_message("a" * 24, include_body=False)
    assert "body_text" not in metadata_only
    assert "attachments" not in metadata_only
    attachment = reader.list_attachments("a" * 24)[0]
    assert attachment["filename"] == "report.pdf"
    assert attachment["mimetype"] == "application/pdf"
    assert attachment["size"] == 12
    assert attachment["available"] is False
    with pytest.raises(ValueError):
        reader.get_message("../../etc/passwd")

    stats = reader.stats()
    assert stats["messages"] == 2
    assert stats["mode"] == "read-only archive"


def test_reader_inbox_filter_excludes_unread_mail_moved_elsewhere(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    writer.upsert(message_record("a" * 24, account="gmail", folder="INBOX", uid=1))
    writer.upsert(message_record("b" * 24, account="outlook", folder="Inbox", uid=2))
    writer.upsert(message_record("c" * 24, account="work", folder="Archive", uid=3))
    writer.upsert(message_record("d" * 24, account="gmail", folder="[Gmail]/All Mail", uid=4))

    reader = ArchiveReader(data)
    assert reader.count_messages(unread_only=True) == 4
    assert reader.count_messages(unread_only=True, inbox_only=True) == 2
    assert {row["id"] for row in reader.list_recent(unread_only=True, inbox_only=True)} == {
        "a" * 24,
        "b" * 24,
    }


def test_list_recent_reads_metadata_without_loading_message_bodies(archive_dir: Path) -> None:
    statements: list[str] = []

    class RecordingReader(ArchiveReader):
        def _collect(self, sql: str, params: list, limit: int) -> list[sqlite3.Row]:
            statements.append(sql)
            return super()._collect(sql, params, limit)

    assert RecordingReader(archive_dir).list_recent(limit=10)
    assert len(statements) == 1
    projection = statements[0].partition("FROM messages")[0]
    assert "SELECT *" not in projection
    assert "body_text" not in projection
    assert "body_html" not in projection


def test_thread_folder_sync_and_safe_attachment_download(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    attachment_key = generate_key()
    writer = ArchiveWriter(data, attachment_key=attachment_key)
    root = parse_message(account="gmail", folder="INBOX", uid=1, raw=_raw_message(), flags=())
    reply = dataclasses.replace(
        root,
        stable_id="e" * 24,
        uid=2,
        message_id="<mail-2@example.test>",
        in_reply_to="mail-1@example.test",
        references_ids=("mail-1@example.test",),
        date_received="2026-08-17T11:00:00+00:00",
        attachments=(),
        has_attachments=False,
    )
    writer.upsert(root)
    writer.upsert(reply)
    writer.set_sync_state("gmail", "INBOX", "777", 2)
    reader = ArchiveReader(data, attachment_key=attachment_key)

    assert [item["id"] for item in reader.get_thread(reply.stable_id)] == [
        root.stable_id,
        reply.stable_id,
    ]
    assert reader.list_folders("gmail")[0]["messages"] == 2
    assert reader.sync_status()[0]["last_uid"] == 2

    attachments = reader.list_attachments(root.stable_id)
    assert attachments[0]["filename"] == "report.pdf"
    assert attachments[0]["available"] is True
    downloaded = reader.download_attachment(root.stable_id, attachments[0]["attachment_id"])
    assert downloaded["filename"] == "report.pdf"
    assert base64.b64decode(downloaded["content_base64"]) == b"%PDF-1.4\npdf-content"
    with sqlite3.connect(data / "mail-hot.db") as conn:
        encrypted = bytes(conn.execute("SELECT ciphertext FROM attachment_blobs").fetchone()[0])
    assert b"pdf-content" not in encrypted
    with pytest.raises(AttachmentPolicyError, match="limit"):
        reader.download_attachment(root.stable_id, attachments[0]["attachment_id"], max_bytes=5)
    with pytest.raises(RuntimeError, match="authentication"):
        ArchiveReader(data, attachment_key=generate_key()).download_attachment(
            root.stable_id, attachments[0]["attachment_id"]
        )
    with pytest.raises(ValueError, match="attachment id"):
        reader.download_attachment(root.stable_id, "../../etc/passwd")


def test_attachment_reupsert_with_changed_mimetype_keeps_blob_decryptable(
    tmp_path: Path,
) -> None:
    # Bridge ingest and native sync can present the same attachment with a
    # different mimetype string. The blob AAD binds the mimetype at encryption
    # time, so the later upsert must not rewrite the row and brick the blob.
    data = tmp_path / "archive"
    attachment_key = generate_key()
    writer = ArchiveWriter(data, attachment_key=attachment_key)
    record = parse_message(account="gmail", folder="INBOX", uid=1, raw=_raw_message(), flags=())
    writer.upsert(record)
    renamed = dataclasses.replace(
        record,
        attachments=tuple(
            dataclasses.replace(item, mimetype="application/octet-stream")
            for item in record.attachments
        ),
    )
    writer.upsert(renamed)
    reader = ArchiveReader(data, attachment_key=attachment_key)
    attachments = reader.list_attachments(record.stable_id)
    downloaded = reader.download_attachment(record.stable_id, attachments[0]["attachment_id"])
    assert base64.b64decode(downloaded["content_base64"]) == b"%PDF-1.4\npdf-content"


def test_search_skips_shards_without_fts_index(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    record = parse_message(account="gmail", folder="INBOX", uid=1, raw=_raw_message(), flags=())
    writer.upsert(record)
    # A seeded shard without messages_fts must degrade, not poison every search.
    crippled = data / "mail-2019.db"
    with sqlite3.connect(crippled) as conn:
        conn.executescript("CREATE TABLE messages(id TEXT PRIMARY KEY, date_received TEXT);")
    crippled.chmod(0o600)
    reader = ArchiveReader(data)
    results = reader.search("Quarterly")
    assert [item["id"] for item in results] == [record.stable_id]
    # Invalid FTS5 syntax falls back to a literal search instead of failing.
    assert reader.search('"unbalanced') == []


def test_concurrent_first_open_runs_migrations_once(tmp_path: Path) -> None:
    import concurrent.futures

    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    record = parse_message(account="gmail", folder="INBOX", uid=1, raw=_raw_message(), flags=())
    writer.upsert(record)
    hot = data / "mail-hot.db"
    with sqlite3.connect(hot) as conn:
        conn.execute("DELETE FROM archive_schema_migrations")
        conn.commit()

    def reopen() -> None:
        connection = open_writer(hot)
        connection.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for future in [pool.submit(reopen) for _ in range(4)]:
            future.result()
    with sqlite3.connect(hot) as conn:
        names = [
            row[0]
            for row in conn.execute("SELECT name FROM archive_schema_migrations ORDER BY name")
        ]
    assert names == [
        "002_message_locations",
        "003_html_only_body_text",
        "004_canonical_logical_location",
        "005_provider_uid_observations",
    ]


def test_archive_tracks_multiple_provider_locations_and_move_tombstones(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    inbox = parse_message(
        account="gmail", folder="INBOX", uid=7, raw=_raw_message(), flags=("\\Seen",)
    )
    all_mail = dataclasses.replace(inbox, folder="[Gmail]/All Mail", uid=20)
    writer.upsert(inbox, uid_validity="111")
    writer.upsert(all_mail, uid_validity="222")
    reader = ArchiveReader(data)

    assert reader.get_message(inbox.stable_id)["folder"] == "INBOX"
    assert [item["folder"] for item in reader.message_locations(inbox.stable_id)] == [
        "INBOX",
        "[Gmail]/All Mail",
    ]
    writer.confirm_move(
        inbox.stable_id,
        account="gmail",
        source="INBOX",
        destination="[Gmail]/All Mail",
        destination_uid=20,
        destination_uid_validity="222",
        destination_flags=("\\Seen",),
    )
    locations = reader.message_locations(inbox.stable_id)
    assert locations == [
        {
            "account": "gmail",
            "folder": "[Gmail]/All Mail",
            "uid": 20,
            "uid_validity": "222",
            "flags": ["\\Seen"],
            "raw_body_sha256": inbox.raw_body_sha256,
            "observed_at": locations[0]["observed_at"],
        }
    ]


def test_read_only_folder_snapshot_reconciles_external_moves(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    inbox = parse_message(account="gmail", folder="INBOX", uid=7, raw=_raw_message(), flags=())
    all_mail = dataclasses.replace(inbox, folder="[Gmail]/All Mail", uid=20)
    writer.upsert(inbox, uid_validity="111")
    writer.upsert(all_mail, uid_validity="222")

    result = writer.reconcile_folder_snapshot("gmail", "INBOX", "111", set())
    assert result == {"deactivated": 1, "reactivated": 0, "flags_updated": 0}
    assert ArchiveReader(data).get_message(inbox.stable_id)["folder"] == "[Gmail]/All Mail"
    assert [item["folder"] for item in ArchiveReader(data).message_locations(inbox.stable_id)] == [
        "[Gmail]/All Mail"
    ]


def test_location_scoped_flags_do_not_overwrite_an_independent_copy(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    inbox = parse_message(account="icloud", folder="INBOX", uid=7, raw=_raw_message(), flags=())
    archived = dataclasses.replace(inbox, folder="Archive", uid=20)
    writer.upsert(inbox, uid_validity="111")
    writer.upsert(archived, uid_validity="222")

    writer.update_location_flags(
        inbox.stable_id,
        account="icloud",
        folder="INBOX",
        uid=7,
        flags=("\\Seen", "\\Flagged"),
    )
    locations = {
        item["folder"]: item for item in ArchiveReader(data).message_locations(inbox.stable_id)
    }
    assert set(locations["INBOX"]["flags"]) == {"\\Seen", "\\Flagged"}
    assert locations["Archive"]["flags"] == []
    with pytest.raises(ValueError, match="location not found"):
        writer.update_location_flags(
            inbox.stable_id,
            account="icloud",
            folder="INBOX",
            uid=999,
            flags=("\\Seen",),
        )


def test_attachment_policy_rejects_executables_macros_and_zip_bombs() -> None:
    with pytest.raises(AttachmentPolicyError, match="executable"):
        validate_download(
            filename="report.pdf",
            mimetype="application/pdf",
            content=b"MZ" + b"x" * 100,
            requested_max_bytes=1024,
        )
    with pytest.raises(AttachmentPolicyError, match="forbidden"):
        validate_download(
            filename="macro.xlsm",
            mimetype="application/vnd.ms-excel",
            content=b"content",
            requested_max_bytes=1024,
        )

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", b"0" * (1024 * 1024))
    with pytest.raises(AttachmentPolicyError, match="compression ratio"):
        validate_download(
            filename="document.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            content=stream.getvalue(),
            requested_max_bytes=5 * 1024 * 1024,
        )


def test_attachment_policy_rejects_mime_spoofing_and_unsafe_office_archives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert attachment_policy.safe_filename("../\x00..") == "attachment"
    assert validate_download(
        filename="../photo.jpeg",
        mimetype="IMAGE/JPEG; charset=binary",
        content=b"\xff\xd8\xffimage",
        requested_max_bytes=1024,
    ) == ("photo.jpeg", "image/jpeg")

    rejected = (
        ("data.bin", "application/octet-stream", b"data", "allowlisted"),
        ("report.pdf", "application/pdf", b"not-pdf", "PDF"),
        ("image.png", "image/png", b"not-png", "PNG"),
        ("image.jpeg", "image/jpeg", b"not-jpeg", "JPEG"),
        ("notes.txt", "text/plain", b"text\x00binary", "binary"),
        ("notes", "text/plain", b"#!/bin/sh", "executable"),
    )
    for filename, mimetype, content, error in rejected:
        with pytest.raises(AttachmentPolicyError, match=error):
            validate_download(
                filename=filename,
                mimetype=mimetype,
                content=content,
                requested_max_bytes=1024,
            )

    office_mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    with pytest.raises(AttachmentPolicyError, match="malformed"):
        validate_download(
            filename="document.docx",
            mimetype=office_mime,
            content=b"not-a-zip",
            requested_max_bytes=1024,
        )

    macro = io.BytesIO()
    with zipfile.ZipFile(macro, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"macro")
    with pytest.raises(AttachmentPolicyError, match="macro"):
        validate_download(
            filename="document.docx",
            mimetype=office_mime,
            content=macro.getvalue(),
            requested_max_bytes=1024,
        )

    entries = io.BytesIO()
    with zipfile.ZipFile(entries, "w") as archive:
        archive.writestr("one.xml", b"1")
        archive.writestr("two.xml", b"2")
    monkeypatch.setattr(attachment_policy, "MAX_ZIP_ENTRIES", 1)
    with pytest.raises(AttachmentPolicyError, match="too many entries"):
        validate_download(
            filename="document.docx",
            mimetype=office_mime,
            content=entries.getvalue(),
            requested_max_bytes=1024,
        )

    monkeypatch.setattr(attachment_policy, "MAX_ZIP_ENTRIES", 1000)
    monkeypatch.setattr(attachment_policy, "MAX_ZIP_UNCOMPRESSED_BYTES", 1)
    with pytest.raises(AttachmentPolicyError, match="expands"):
        validate_download(
            filename="document.docx",
            mimetype=office_mime,
            content=entries.getvalue(),
            requested_max_bytes=1024,
        )


def test_reader_deduplicates_seed_and_copy_only_rollover_preserves_source_and_attachments(
    tmp_path: Path,
) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    writer.upsert(
        message_record(
            "c" * 24,
            received="2025-01-01T00:00:00+00:00",
            attachments=(AttachmentRecord("invoice.pdf", "application/pdf", 99),),
        )
    )
    first = writer.rollover_copy_only(
        scheduled_slot="2026-08-17T04:10:00+01:00", cutoff=dt.date(2026, 8, 10)
    )
    assert first["copied"] == 1
    assert first["replayed"] is False
    replay = writer.rollover_copy_only(
        scheduled_slot="2026-08-17T04:10:00+01:00", cutoff=dt.date(2026, 8, 10)
    )
    assert replay["replayed"] is True
    assert ArchiveReader(data).stats()["messages"] == 1
    with open_readonly(data / "mail-hot.db") as hot:
        assert hot.execute("SELECT count(*) FROM messages").fetchone()[0] == 1
    with open_readonly(data / "mail-2025.db") as year:
        assert year.execute("SELECT count(*) FROM messages").fetchone()[0] == 1
        assert year.execute("SELECT count(*) FROM message_locations").fetchone()[0] == 1
        assert year.execute("SELECT count(*) FROM provider_uid_observations").fetchone()[0] == 1
        assert year.execute("SELECT filename FROM attachments").fetchone()[0] == "invoice.pdf"


class FakeImap:
    def __init__(self, raw: bytes, *, uid_validity: bytes = b"777", search: bytes = b"10 11"):
        self.raw = raw
        self.uid_validity = uid_validity
        self.search = search
        self.calls: list[tuple] = []
        self.auth_fail_once = False

    def authenticate(self, mechanism, callback):
        self.calls.append(("authenticate", mechanism, callback(b"challenge")))
        if self.auth_fail_once:
            self.auth_fail_once = False
            raise imaplib.IMAP4.error("expired token")
        return "OK", []

    def login(self, address, password):
        self.calls.append(("login", address, password))
        return "OK", []

    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return "OK", [str(len(self.search.split())).encode()]

    def response(self, name):
        self.calls.append(("response", name))
        return "UIDVALIDITY", [self.uid_validity]

    def uid(self, command, *args):
        self.calls.append(("uid", command, *args))
        if command == "SEARCH":
            return "OK", [self.search]
        if command == "FETCH":
            if args[0] == "1:*":
                return "OK", [
                    f"{index} (UID {int(uid)} FLAGS (\\Seen))".encode()
                    for index, uid in enumerate(self.search.split(), 1)
                ]
            uid = int(args[0])
            metadata = (
                f"1 (UID {uid} FLAGS (\\Seen) RFC822.SIZE {len(self.raw)} "
                f"BODY[] {{{len(self.raw)}}}"
            ).encode()
            return "OK", [(metadata, self.raw), b")"]
        raise AssertionError(command)

    def logout(self):
        self.calls.append(("logout",))
        return "BYE", []


def test_read_only_imap_sync_adopts_legacy_watermark_and_never_mutates(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    writer.upsert(message_record("d" * 24, uid=9))
    with sqlite3.connect(data / "mail-hot.db") as conn:
        conn.executescript(
            """
            CREATE TABLE sync_state(account TEXT,folder TEXT,last_uid INTEGER,last_synced_at TEXT,
              PRIMARY KEY(account,folder));
            INSERT INTO sync_state VALUES ('gmail','INBOX',10,'2026-08-17T00:00:00Z');
            """
        )
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    raw = _raw_message()
    fake = FakeImap(raw)
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "oauth-secret",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="gmail",
        address="user@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        credential_record="oauth:gmail",
        folders=("INBOX",),
    )
    result = sync.sync_account(account)
    assert result["inserted"] == 2
    assert result["folders"]["INBOX"]["historical_uid_discoveries"] == 1
    search_call = next(call for call in fake.calls if call[:2] == ("uid", "SEARCH"))
    assert search_call[-1] == "ALL"
    assert any(call[0] == "select" and call[-1] is True for call in fake.calls)
    assert any(call[:2] == ("uid", "FETCH") and "BODY.PEEK" in call[-1] for call in fake.calls)
    assert not any(
        call[0].lower() in {"store", "move", "copy", "expunge", "delete"} for call in fake.calls
    )
    assert all(
        str(item).upper() not in {"STORE", "MOVE", "COPY", "EXPUNGE"}
        for call in fake.calls
        for item in call
    )
    assert writer.sync_state("gmail", "INBOX") == ("777", 11)


def test_read_only_sync_refreshes_existing_location_flags(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    raw = _raw_message()
    record = parse_message(account="gmail", folder="INBOX", uid=11, raw=raw, flags=())
    writer.upsert(record, uid_validity="777")
    writer.set_sync_state("gmail", "INBOX", "777", 11)
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    fake = FakeImap(raw, uid_validity=b"777", search=b"11")
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "oauth-secret",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="gmail",
        address="user@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        credential_record="oauth:gmail",
        folders=("INBOX",),
    )

    result = sync.sync_account(account)
    assert result["inserted"] == 0
    assert result["folders"]["INBOX"]["location_flags_updated"] == 1
    locations = ArchiveReader(data).message_locations(record.stable_id)
    assert locations[0]["flags"] == ["\\Seen"]
    assert not any(call[:2] == ("uid", "FETCH") and "BODY.PEEK" in call[-1] for call in fake.calls)


@pytest.mark.parametrize("shard_only", [False, True])
def test_read_only_sync_discovers_move_destination_below_watermark(
    tmp_path: Path, shard_only: bool
) -> None:
    class MovingFakeImap(FakeImap):
        def __init__(self, raw: bytes):
            super().__init__(raw, search=b"")
            self.selected = ""
            self.folder_state = {
                "INBOX": (b"inbox-v", b""),
                "[Gmail]/All Mail": (b"all-v", b"200"),
                "Unrelated": (b"unrelated-v", b"50"),
            }

        def select(self, folder, readonly=False):
            self.calls.append(("select", folder, readonly))
            self.selected = str(folder).strip('"')
            return "OK", [str(len(self.folder_state[self.selected][1].split())).encode()]

        def response(self, name):
            self.calls.append(("response", name))
            return "UIDVALIDITY", [self.folder_state[self.selected][0]]

        def uid(self, command, *args):
            self.search = self.folder_state[self.selected][1]
            return super().uid(command, *args)

    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    raw = _raw_message()
    inbox = parse_message(account="gmail", folder="INBOX", uid=100, raw=raw, flags=())
    all_mail = dataclasses.replace(inbox, folder="[Gmail]/All Mail", uid=200)
    writer.upsert(inbox, uid_validity="inbox-v")
    writer.upsert(all_mail, uid_validity="all-v")
    with sqlite3.connect(data / "mail-hot.db") as conn:
        conn.execute(
            "UPDATE messages SET raw_size=?,date_received=? WHERE id=?",
            (999_999, "2026-08-16T10:00:01+00:00", inbox.stable_id),
        )
        conn.commit()
    writer.set_sync_state("gmail", "INBOX", "inbox-v", 100)
    writer.set_sync_state("gmail", "[Gmail]/All Mail", "all-v", 200)
    # The provider reused a destination UID below this existing watermark.
    writer.set_sync_state("gmail", "Unrelated", "unrelated-v", 500)
    if shard_only:
        writer.rollover_copy_only(scheduled_slot="test", cutoff=dt.date(2027, 1, 1))
        with open_writer(writer.hot_path) as conn:
            conn.execute("DELETE FROM messages WHERE id=?", (inbox.stable_id,))
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    fake = MovingFakeImap(raw)
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "oauth-secret",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="gmail",
        address="user@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        credential_record="oauth:gmail",
        folders=("INBOX", "[Gmail]/All Mail", "Unrelated"),
    )

    result = sync.sync_account(account)

    assert result["inserted"] == 1
    assert result["folders"]["Unrelated"]["historical_uid_discoveries"] == 1
    assert result["folders"]["Unrelated"]["historical_uid_discoveries_remaining"] == 0
    assert writer.sync_state("gmail", "Unrelated") == ("unrelated-v", 500)
    assert ArchiveReader(data).get_message(inbox.stable_id)["folder"] == "Unrelated"
    locations = {
        item["folder"]: item for item in ArchiveReader(data).message_locations(inbox.stable_id)
    }
    assert set(locations) == {"Unrelated", "[Gmail]/All Mail"}
    assert locations["Unrelated"]["uid"] == 50
    with open_readonly(data / "mail-hot.db") as conn:
        preserved = conn.execute(
            "SELECT raw_size,date_received FROM messages WHERE id=?", (inbox.stable_id,)
        ).fetchone()
    assert tuple(preserved) == (999_999, "2026-08-16T10:00:01+00:00")
    assert not any(
        call[0].lower() in {"store", "move", "copy", "append", "expunge", "delete"}
        for call in fake.calls
    )


def test_read_only_sync_tracks_duplicate_uids_in_one_folder_without_refetching(
    tmp_path: Path,
) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    raw = _raw_message()
    record = parse_message(account="work", folder="Archive", uid=10, raw=raw, flags=())
    writer.upsert(record, uid_validity="archive-v")
    writer.set_sync_state("work", "Archive", "archive-v", 20)
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    fake = FakeImap(raw, uid_validity=b"archive-v", search=b"10 11")
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "oauth-secret",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="work",
        address="user@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        credential_record="oauth:work",
        folders=("Archive",),
    )

    first = sync.sync_account(account)
    second = sync.sync_account(account)

    assert first["folders"]["Archive"]["historical_uid_discoveries"] == 1
    assert first["inserted"] == 1
    assert second["folders"]["Archive"]["historical_uid_discoveries"] == 0
    assert second["inserted"] == 0
    assert writer.known_location_uids("work", "Archive", "archive-v") == {10, 11}
    with open_readonly(data / "mail-hot.db") as conn:
        assert (
            conn.execute(
                "SELECT count(*) FROM provider_uid_observations "
                "WHERE account='work' AND folder='Archive'"
            ).fetchone()[0]
            == 2
        )

    fake.search = b"11"
    third = sync.sync_account(account)
    assert third["inserted"] == 0
    assert ArchiveReader(data).message_locations(record.stable_id)[0]["uid"] == 11

    fake.search = b"10 11"
    fourth = sync.sync_account(account)
    assert fourth["inserted"] == 0
    assert ArchiveReader(data).message_locations(record.stable_id)[0]["uid"] == 11


def test_location_observation_rejects_conflicting_raw_identity(tmp_path: Path) -> None:
    writer = ArchiveWriter(tmp_path / "archive")
    record = parse_message(account="gmail", folder="INBOX", uid=10, raw=_raw_message(), flags=())
    writer.upsert(record, uid_validity="inbox-v")
    conflicting = dataclasses.replace(
        record,
        folder="Unrelated",
        uid=20,
        body_text="different content",
        raw_body_sha256="0" * 64,
    )

    with pytest.raises(RuntimeError, match="body identity conflicts"):
        writer.observe_location(conflicting, uid_validity="unrelated-v")
    with pytest.raises(RuntimeError, match="provider UID identity conflicts"):
        writer.observe_location(
            dataclasses.replace(
                record,
                stable_id="2" * 24,
                message_id="different@example.test",
            ),
            uid_validity="inbox-v",
        )
    assert {
        item["folder"]
        for item in ArchiveReader(tmp_path / "archive").message_locations(record.stable_id)
    } == {"INBOX"}


def test_location_observation_accepts_provider_reencoded_equivalent_message(
    tmp_path: Path,
) -> None:
    writer = ArchiveWriter(tmp_path / "archive", attachment_key=b"a" * 32)
    raw = _raw_message()
    reencoded_raw = raw.replace(
        b"Date: Sun, 16 Aug 2026 10:00:00 +0000\n",
        b"Date: Sun, 16 Aug 2026 10:00:55 +0000\nX-Transport-Rewritten: yes\n",
    )
    original = parse_message(account="gmail", folder="INBOX", uid=10, raw=raw, flags=())
    destination = parse_message(
        account="gmail",
        folder="Unrelated",
        uid=20,
        raw=reencoded_raw,
        flags=("\\Seen",),
    )
    assert original.stable_id == destination.stable_id
    assert original.raw_body_sha256 != destination.raw_body_sha256
    assert original.body_text == destination.body_text
    writer.upsert(original, uid_validity="inbox-v")

    writer.observe_location(destination, uid_validity="unrelated-v")

    locations = {
        item["folder"]: item
        for item in ArchiveReader(tmp_path / "archive").message_locations(original.stable_id)
    }
    assert set(locations) == {"INBOX", "Unrelated"}
    assert locations["Unrelated"]["raw_body_sha256"] == destination.raw_body_sha256
    with open_readonly(tmp_path / "archive" / "mail-hot.db") as conn:
        preserved = conn.execute(
            "SELECT date_received,raw_size,raw_body_sha256 FROM messages WHERE id=?",
            (original.stable_id,),
        ).fetchone()
    assert tuple(preserved) == (
        original.date_received,
        original.raw_size,
        original.raw_body_sha256,
    )

    plain = message_record(
        "1" * 24,
        account="work",
        folder="INBOX",
        uid=30,
        received="2026-08-16T10:00:00+00:00",
    )
    writer.upsert(plain, uid_validity="plain-inbox-v")
    writer.observe_location(
        dataclasses.replace(
            plain,
            folder="Archive",
            uid=31,
            date_received="2026-08-16T10:00:55+00:00",
            raw_size=plain.raw_size + 362,
            raw_body_sha256="e" * 64,
        ),
        uid_validity="plain-archive-v",
    )
    assert {
        item["folder"]
        for item in ArchiveReader(tmp_path / "archive").message_locations(plain.stable_id)
    } == {"Archive", "INBOX"}


def test_provider_reencoding_identity_helpers_and_conflicts(tmp_path: Path) -> None:
    assert _normalized_reference_ids('["<B@example.test>", "a@example.test"]') == (
        "a@example.test",
        "b@example.test",
    )
    assert _normalized_reference_ids("<B@example.test> <a@example.test>") == (
        "a@example.test",
        "b@example.test",
    )
    assert _normalized_reference_ids("B@example.test a@example.test") == (
        "a@example.test",
        "b@example.test",
    )
    assert _dates_are_provider_equivalent("same", "same")
    assert not _dates_are_provider_equivalent("", "2026-08-16T10:00:00+00:00")
    assert not _dates_are_provider_equivalent("invalid", "also-invalid")
    assert not _dates_are_provider_equivalent(
        "2026-08-16T10:00:00+00:00", "2026-08-16T10:06:00+00:00"
    )

    writer = ArchiveWriter(tmp_path / "archive", attachment_key=b"b" * 32)
    record = parse_message(account="gmail", folder="INBOX", uid=10, raw=_raw_message(), flags=())
    writer.upsert(record, uid_validity="inbox-v")
    changed_attachment = dataclasses.replace(
        record.attachments[0], content=b"%PDF-1.4\nbad-content"
    )
    conflicts = (
        {"message_id": ""},
        {"references_ids": ("different@example.test",)},
        {"has_attachments": False},
        {"date_received": "2026-08-16T10:06:00+00:00"},
        {"recipients_to": "different@example.test"},
        {"reply_to": "different@example.test"},
        {"attachments": ()},
        {"attachments": (changed_attachment,)},
    )
    for uid, changes in enumerate(conflicts, start=20):
        conflicting = dataclasses.replace(
            record,
            folder="Unrelated",
            uid=uid,
            raw_body_sha256=str(uid).zfill(64),
            **changes,
        )
        with pytest.raises(RuntimeError, match="body identity conflicts"):
            writer.observe_location(conflicting, uid_validity="unrelated-v")
    assert {
        item["folder"]
        for item in ArchiveReader(tmp_path / "archive").message_locations(record.stable_id)
    } == {"INBOX"}


def test_duplicate_delivery_with_rewritten_headers_does_not_block_sync(tmp_path: Path) -> None:
    raw = _raw_message()
    original = parse_message(account="work", folder="INBOX", uid=10, raw=raw, flags=())
    original = dataclasses.replace(
        original,
        reply_to="reply@example.test",
        recipients_to="first@example.test, second@example.test",
        recipients_cc="reply@example.test",
        raw_size=original.raw_size + 12000,
    )
    message = email.message_from_bytes(raw)
    message.replace_header("To", "Second <SECOND@example.test>, First <first@example.test>")
    message["Reply-To"] = "Reply Person <reply@example.test>"
    message["Cc"] = "Reply Person <reply@example.test>"
    duplicate_raw = message.as_bytes()
    writer = ArchiveWriter(tmp_path / "archive", attachment_key=b"a" * 32)
    writer.upsert(original, uid_validity="777")
    writer.set_sync_state("work", "INBOX", "777", 10)
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )

    class DuplicateDeliveryImap(FakeImap):
        def uid(self, command, *args):
            if command == "FETCH" and args[0] == "12":
                self.raw = duplicate_raw.replace(b"mail-1@example.test", b"mail-2@example.test")
            return super().uid(command, *args)

    fake = DuplicateDeliveryImap(duplicate_raw, search=b"10 11 12")
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "oauth-secret",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="work",
        address="user@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        credential_record="oauth:work",
        folders=("INBOX",),
    )
    assert sync.sync_account(account)["inserted"] == 2
    assert writer.sync_state("work", "INBOX") == ("777", 12)
    with open_readonly(writer.hot_path) as conn:
        preserved = conn.execute(
            "SELECT * FROM messages WHERE id=?", (original.stable_id,)
        ).fetchone()
        assert preserved["raw_body_sha256"] == original.raw_body_sha256
        assert preserved["recipients_to"] == original.recipients_to
        assert preserved["raw_size"] == original.raw_size
        assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 2


def _reencoded_sync(tmp_path: Path, *, search: bytes):
    """Archive one message, then serve a provider re-encoded copy plus new mail."""
    raw = _raw_message()
    original = parse_message(account="work", folder="INBOX", uid=10, raw=raw, flags=())
    writer = ArchiveWriter(tmp_path / "archive", attachment_key=b"a" * 32)
    writer.upsert(original, uid_validity="777")
    writer.set_sync_state("work", "INBOX", "777", 10)
    reencoded = raw.replace(b"Body with Bearer", b"Body regenerated by provider")
    unrelated = raw.replace(b"mail-1@example.test", b"mail-2@example.test")

    class ReencodingImap(FakeImap):
        def uid(self, command, *args):
            if command == "FETCH" and args[0] != "1:*":
                self.raw = reencoded if args[0] == "11" else unrelated
            return super().uid(command, *args)

    fake = ReencodingImap(raw, search=search)
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=CredentialStore(
            tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
        ),
        oauth_access_token=lambda _account: "oauth-secret",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="work",
        address="user@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        credential_record="oauth:work",
        folders=("INBOX",),
    )
    return writer, sync, account, fake, original


def test_identity_conflict_is_quarantined_without_blocking_the_folder(tmp_path: Path) -> None:
    writer, sync, account, fake, original = _reencoded_sync(tmp_path, search=b"11 12")

    result = sync.sync_account(account)

    folder = result["folders"]["INBOX"]
    assert result["inserted"] == 2
    assert folder["identity_conflicts"] == [{"uid": 11, "stable_id": original.stable_id}]
    assert writer.sync_state("work", "INBOX") == ("777", 12)
    with open_readonly(writer.hot_path) as conn:
        preserved = conn.execute(
            "SELECT raw_body_sha256,body_text FROM messages WHERE id=?", (original.stable_id,)
        ).fetchone()
        assert preserved["raw_body_sha256"] == original.raw_body_sha256
        assert "regenerated" not in preserved["body_text"]
        assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 2
        quarantined = conn.execute(
            "SELECT * FROM provider_identity_conflicts WHERE uid=11"
        ).fetchone()
        assert quarantined["stable_id"] == original.stable_id
        assert quarantined["archive_raw_body_sha256"] == original.raw_body_sha256
        assert quarantined["provider_raw_body_sha256"] != original.raw_body_sha256
        assert quarantined["cleared_at"] is None
        assert (
            conn.execute("SELECT count(*) FROM provider_uid_observations WHERE uid=11").fetchone()[
                0
            ]
            == 0
        )
    assert all(
        item["uid"] != 11
        for item in ArchiveReader(writer.data_dir).message_locations(original.stable_id)
    )
    assert not any(
        call[0].lower() in {"store", "move", "copy", "expunge", "delete"} for call in fake.calls
    )

    fetches = sum(call[:2] == ("uid", "FETCH") and call[2] != "1:*" for call in fake.calls)
    second = sync.sync_account(account)
    assert second["folders"]["INBOX"]["identity_conflicts"] == [
        {"uid": 11, "stable_id": original.stable_id}
    ]
    assert sum(call[:2] == ("uid", "FETCH") and call[2] != "1:*" for call in fake.calls) == (
        fetches
    )


def test_quarantine_clears_when_the_provider_copy_leaves_and_rediscovers_when_cleared(
    tmp_path: Path,
) -> None:
    writer, sync, account, fake, original = _reencoded_sync(tmp_path, search=b"11 12")
    sync.sync_account(account)
    assert 11 in writer.known_location_uids("work", "INBOX", "777")

    fake.search = b"12"
    gone = sync.sync_account(account)
    assert gone["folders"]["INBOX"]["identity_conflicts"] == []
    assert 11 not in writer.known_location_uids("work", "INBOX", "777")
    with open_readonly(writer.hot_path) as conn:
        assert (
            conn.execute(
                "SELECT cleared_at FROM provider_identity_conflicts WHERE uid=11"
            ).fetchone()[0]
            is not None
        )

    fake.search = b"11 12"
    back = sync.sync_account(account)
    assert back["folders"]["INBOX"]["historical_uid_discoveries"] == 1
    assert back["folders"]["INBOX"]["identity_conflicts"] == [
        {"uid": 11, "stable_id": original.stable_id}
    ]


def test_identity_conflict_keeps_its_context_and_rolls_back_only_its_record(
    tmp_path: Path,
) -> None:
    writer = ArchiveWriter(tmp_path / "archive")
    record = parse_message(account="gmail", folder="INBOX", uid=10, raw=_raw_message(), flags=())
    writer.upsert(record, uid_validity="inbox-v")
    conflicting = dataclasses.replace(
        record, uid=20, body_text="different content", raw_body_sha256="0" * 64
    )
    with pytest.raises(ProviderIdentityConflict) as raised:
        writer.observe_location(conflicting, uid_validity="inbox-v")
    assert f"stable_id={record.stable_id}" in str(raised.value)
    assert raised.value.archive_raw_body_sha256 == record.raw_body_sha256

    version = writer.state_version("gmail")
    result = writer.apply_folder_snapshot(
        "gmail",
        "INBOX",
        "inbox-v",
        {20},
        {20: ()},
        [conflicting],
        expected_version=version,
        last_uid=20,
    )
    assert result["identity_conflicts"] == [{"uid": 20, "stable_id": record.stable_id}]
    assert result["deactivated"] == 1
    assert writer.sync_state("gmail", "INBOX") == ("inbox-v", 20)


@pytest.mark.parametrize(
    ("left", "right", "equivalent"),
    [
        ("", "", True),
        ("", "a@example.test", False),
        ("Alice <a@example.test>", "a@example.test", True),
        ("a@example.test, b@example.test", "B@example.test, A@example.test", True),
        ("a@example.test, a@example.test", "a@example.test", False),
        ("a@example.test", "b@example.test", False),
        ("invalid", "Invalid", False),
        ("a@example.test, invalid", "a@example.test", False),
    ],
)
def test_provider_mailbox_equivalence(left: str, right: str, equivalent: bool) -> None:
    assert _mailboxes_are_provider_equivalent(left, right) is equivalent


def test_uidvalidity_change_restarts_safely_and_password_auth_is_host_local(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    writer.set_sync_state("icloud", "INBOX", "old", 999)
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    credentials.put("password:icloud", {"password": "app-password"})
    fake = FakeImap(_raw_message(), uid_validity=b"new", search=b"1")
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "unused",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="icloud",
        address="icloud@example.test",
        imap_host="imap.example.test",
        credential_record="password:icloud",
        folders=("INBOX",),
    )
    sync.sync_account(account)
    assert ("login", "icloud@example.test", "app-password") in fake.calls
    search_call = next(call for call in fake.calls if call[:2] == ("uid", "SEARCH"))
    assert search_call[-1] == "ALL"
    assert _imap_utf7_encode("存档") == "&W1hoYw-"


def test_read_sync_forces_oauth_refresh_once_after_authentication_rejection(
    tmp_path: Path,
) -> None:
    writer = ArchiveWriter(tmp_path / "archive")
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    fake = FakeImap(_raw_message(), search=b"")
    fake.auth_fail_once = True
    requests: list[bool] = []

    def oauth(_account: AccountConfig, *, force_refresh: bool = False) -> str:
        requests.append(force_refresh)
        return "fresh" if force_refresh else "cached"

    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=oauth,
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="outlook",
        address="user@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        credential_record="oauth:outlook",
        folders=("INBOX",),
    )
    assert sync.sync_account(account)["auth"] == "ok"
    assert requests == [False, True]


@pytest.mark.parametrize(
    "error", [TimeoutError(), ssl.SSLError("wrong version"), imaplib.IMAP4.abort("EOF")]
)
def test_read_sync_retries_transient_connections_without_refreshing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    sync = ReadOnlyMailboxSync(
        archive=ArchiveWriter(tmp_path / "archive"),
        credentials=CredentialStore(
            tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="test"
        ),
        oauth_access_token=lambda _account: "unused",
    )
    calls = []
    sleeps = []
    client = object()

    def authenticate_once(_account, *, force_refresh):
        calls.append(force_refresh)
        if len(calls) < 3:
            raise error
        return client

    monkeypatch.setattr(sync.connector, "authenticate_once", authenticate_once)
    monkeypatch.setattr("evergarden.mail.imap_connector.time.sleep", sleeps.append)
    account = AccountConfig(
        alias="work", address="user@example.test", imap_host="imap.test", auth_kind="oauth2"
    )
    assert sync.authenticate(account) is client
    assert calls == [False, False, False]
    assert sleeps == [1, 2]


@pytest.mark.parametrize(
    "error, expected_calls",
    [
        (TimeoutError(), 3),
        (ssl.SSLCertVerificationError("certificate invalid"), 1),
        (RuntimeError("identity conflict"), 1),
    ],
)
def test_read_sync_connection_retries_are_bounded_and_do_not_bypass_certificates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception, expected_calls: int
) -> None:
    sync = ReadOnlyMailboxSync(
        archive=ArchiveWriter(tmp_path / "archive"),
        credentials=CredentialStore(
            tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="test"
        ),
        oauth_access_token=lambda _account: "unused",
    )
    calls = []

    def authenticate_once(_account, *, force_refresh):
        calls.append(force_refresh)
        raise error

    monkeypatch.setattr(sync.connector, "authenticate_once", authenticate_once)
    monkeypatch.setattr("evergarden.mail.imap_connector.time.sleep", lambda _seconds: None)
    account = AccountConfig(
        alias="work", address="user@example.test", imap_host="imap.test", auth_kind="oauth2"
    )
    with pytest.raises(type(error)):
        sync.authenticate(account)
    assert len(calls) == expected_calls


def test_read_sync_retries_transient_exchange_rejection_without_refreshing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sync = ReadOnlyMailboxSync(
        archive=ArchiveWriter(tmp_path / "archive"),
        credentials=CredentialStore(
            tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="test"
        ),
        oauth_access_token=lambda _account: "unused",
    )
    calls = []
    sleeps = []
    client = object()

    def authenticate_once(_account, *, force_refresh):
        calls.append(force_refresh)
        if len(calls) < 3:
            raise imaplib.IMAP4.error("User is authenticated but not connected.")
        return client

    monkeypatch.setattr(sync.connector, "authenticate_once", authenticate_once)
    monkeypatch.setattr("evergarden.mail.imap_connector.time.sleep", sleeps.append)
    account = AccountConfig(
        alias="outlook", address="user@example.test", imap_host="imap.test", auth_kind="oauth2"
    )
    assert sync.authenticate(account) is client
    assert calls == [False, False, False]
    assert sleeps == [5, 10]

    calls.clear()

    def always_rejected(_account, *, force_refresh):
        calls.append(force_refresh)
        raise imaplib.IMAP4.error("User is authenticated but not connected.")

    monkeypatch.setattr(sync.connector, "authenticate_once", always_rejected)
    with pytest.raises(imaplib.IMAP4.error, match="not connected"):
        sync.authenticate(account)
    # Outlook.com grants roughly one connection in five, so background sync
    # makes twelve fresh connection attempts before reporting the slot failed.
    assert calls == [False] * 12


def test_read_sync_attempts_later_folders_and_reports_partial_failure(tmp_path: Path) -> None:
    class FolderFailingImap(FakeImap):
        def select(self, folder, readonly=False):
            self.calls.append(("select", folder, readonly))
            if folder == "Broken":
                return "NO", []
            return "OK", [b"1"]

    writer = ArchiveWriter(tmp_path / "archive")
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    credentials.put("password:icloud", {"password": "app-password"})
    fake = FolderFailingImap(_raw_message(), search=b"1")
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "unused",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="icloud",
        address="user@example.test",
        imap_host="imap.example.test",
        credential_record="password:icloud",
        folders=("Broken", "INBOX"),
    )

    with pytest.raises(MailboxSyncIncomplete) as failure:
        sync.sync_account(account)
    assert failure.value.result["folders"]["Broken"]["status"] == "failed"
    assert failure.value.result["folders"]["INBOX"]["status"] == "ok"
    assert failure.value.result["inserted"] == 1
    assert [call[1] for call in fake.calls if call[0] == "select"] == [
        "Broken",
        "INBOX",
    ]


def test_archive_sqlite_files_are_private_and_never_follow_symlinks(tmp_path: Path) -> None:
    path = tmp_path / "private-archive" / "mail-hot.db"
    with open_writer(path) as connection:
        connection.execute("SELECT 1")
    assert path.parent.stat().st_mode & 0o077 == 0
    assert path.stat().st_mode & 0o077 == 0
    with open_readonly(path) as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1

    path.chmod(0o644)
    with pytest.raises(RuntimeError, match="mode 0600"):
        open_readonly(path)
    with open_writer(path):
        pass
    assert path.stat().st_mode & 0o077 == 0

    target = tmp_path / "target.db"
    target.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(RuntimeError, match="symlink"):
        open_writer(path)
    with pytest.raises(RuntimeError, match="symlink"):
        open_readonly(path)


@pytest.mark.parametrize("case", ["valid", "body", "attachment", "uid", "legacy"])
def test_observation_validates_and_restores_shard_only_message(tmp_path: Path, case) -> None:
    data = tmp_path / "archive"
    key = b"a" * 32
    writer = ArchiveWriter(data, attachment_key=key)
    record = parse_message(account="gmail", folder="INBOX", uid=10, raw=_raw_message(), flags=())
    writer.upsert(record, uid_validity="inbox-v")
    writer.set_sync_state("gmail", "INBOX", "inbox-v", 10)
    writer.rollover_copy_only(scheduled_slot="test", cutoff=dt.date(2027, 1, 1))
    if case == "legacy":
        with sqlite3.connect(data / "mail-2026.db") as conn:
            conn.execute("ALTER TABLE messages DROP COLUMN reply_to")
    with open_writer(writer.hot_path) as conn:
        conn.execute("DELETE FROM attachment_blobs")
        conn.execute("DELETE FROM attachments")
        conn.execute("DELETE FROM messages")
    writer.reconcile_folder_snapshot("gmail", "INBOX", "inbox-v", set())
    assert writer.has_message(record.stable_id, record.account)
    destination = dataclasses.replace(record, folder="Archive", uid=20, flags=("\\Seen",))
    if case in {"body", "attachment", "uid"}:
        if case == "body":
            destination = dataclasses.replace(
                destination, body_text="different body", raw_body_sha256="0" * 64
            )
        elif case == "attachment":
            destination = dataclasses.replace(
                destination,
                attachments=(dataclasses.replace(record.attachments[0], content=b"changed"),),
                raw_body_sha256="0" * 64,
            )
        else:
            with open_writer(writer.hot_path) as conn:
                conn.execute(
                    "INSERT INTO provider_uid_observations(account,folder,uid_validity,uid,"
                    "stable_id,observed_at) VALUES ('gmail','Archive','archive-v',20,?,?)",
                    ("2" * 24, dt.datetime.now(dt.UTC).isoformat()),
                )
        with pytest.raises(RuntimeError, match="identity conflicts"):
            writer.observe_location(destination, uid_validity="archive-v")
        with open_readonly(writer.hot_path) as conn:
            assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 0
            assert (
                conn.execute(
                    "SELECT count(*) FROM message_locations WHERE folder='Archive'"
                ).fetchone()[0]
                == 0
            )
        return

    writer.observe_location(destination, uid_validity="archive-v")
    writer.set_sync_state("gmail", "Archive", "archive-v", 20)
    reader = ArchiveReader(data, attachment_key=key)
    restored = reader.message_context(record.stable_id)
    assert restored["folder"] == "Archive"
    assert restored["uid"] == 20
    assert restored["flags"] == ["\\Seen"]
    assert restored["raw_body_sha256"] == record.raw_body_sha256
    attachment = reader.list_attachments(record.stable_id)[0]
    downloaded = reader.download_attachment(record.stable_id, attachment["attachment_id"])
    assert base64.b64decode(downloaded["content_base64"]) == record.attachments[0].content
    with open_readonly(writer.hot_path) as hot, open_readonly(data / "mail-2026.db") as shard:
        assert hot.execute("SELECT body_text FROM messages").fetchone()[0] == record.body_text
        for table in ("attachments", "attachment_blobs"):
            query = f"SELECT * FROM {table}"  # noqa: S608 - fixed test table names
            assert [tuple(row) for row in hot.execute(query)] == [
                tuple(row) for row in shard.execute(query)
            ]


def test_fetch_flag_parse_keeps_imap_keywords_and_matches_snapshot_parsing() -> None:
    metadata = r"1 (UID 42 FLAGS (\Seen $Forwarded Junk NotJunk) RFC822.SIZE 100)"
    assert _parse_fetch_flags(metadata) == ("\\Seen", "$Forwarded", "Junk", "NotJunk")
    # Without a FLAGS group the parse degrades to system flags only.
    assert _parse_fetch_flags(r"1 (UID 42 \Seen)") == ("\\Seen",)


def test_quote_folder_quotes_backslash_folders() -> None:
    assert _quote_folder("Odd\\Name") == '"Odd\\\\Name"'
    assert _quote_folder("INBOX") == "INBOX"
    assert _quote_folder("With Space") == '"With Space"'


def test_imap_date_is_locale_independent() -> None:
    import datetime as _dt

    from evergarden.mail.actions import _imap_date

    assert _imap_date(_dt.datetime(2026, 8, 3, tzinfo=_dt.UTC)) == "03-Aug-2026"
    assert _imap_date(_dt.datetime(2026, 12, 31, tzinfo=_dt.UTC)) == "31-Dec-2026"


def test_account_sync_lock_serialises_same_account_and_bounds_the_wait(tmp_path: Path) -> None:
    import threading
    import time

    from evergarden.mail.sync import MailboxSyncBusy, account_sync_lock

    events: list[str] = []
    entered = threading.Event()

    def first() -> None:
        with account_sync_lock(tmp_path, "outlook"):
            events.append("first-start")
            entered.set()
            time.sleep(0.3)
            events.append("first-end")

    thread = threading.Thread(target=first)
    thread.start()
    entered.wait()
    # A different account is never blocked.
    with account_sync_lock(tmp_path, "gmail", wait_seconds=0.1):
        events.append("gmail")
    with pytest.raises(MailboxSyncBusy):
        with account_sync_lock(tmp_path, "outlook", wait_seconds=0.05):
            pass
    with account_sync_lock(tmp_path, "outlook"):
        events.append("second")
    thread.join()
    assert events == ["first-start", "gmail", "first-end", "second"]
    assert (tmp_path / ".sync-outlook.lock").stat().st_mode & 0o077 == 0


def test_read_sync_reconnects_after_a_folder_timeout(tmp_path: Path) -> None:
    clients: list[FakeImap] = []

    class TimingOutImap(FakeImap):
        def select(self, folder, readonly=False):
            self.calls.append(("select", folder, readonly))
            if folder == "Slow" and len(clients) == 1:
                raise TimeoutError("The read operation timed out")
            return "OK", [b"1"]

    def factory(*_args, **_kwargs):
        clients.append(TimingOutImap(_raw_message(), search=b"1"))
        return clients[-1]

    writer = ArchiveWriter(tmp_path / "archive")
    credentials = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    credentials.put("password:icloud", {"password": "app-password"})
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "unused",
        imap_factory=factory,
    )
    account = AccountConfig(
        alias="icloud",
        address="user@example.test",
        imap_host="imap.example.test",
        credential_record="password:icloud",
        folders=("Slow", "INBOX"),
    )

    with pytest.raises(MailboxSyncIncomplete) as failure:
        sync.sync_account(account)
    assert failure.value.result["folders"]["Slow"]["error_class"] == "TimeoutError"
    # The folder after the timeout runs on a fresh connection and succeeds.
    assert failure.value.result["folders"]["INBOX"]["status"] == "ok"
    assert len(clients) == 2
    assert [call[1] for call in clients[1].calls if call[0] == "select"] == ["INBOX"]


def test_search_treats_plain_text_with_fts_operators_literally(archive_dir: Path) -> None:
    reader = ArchiveReader(archive_dir)
    # Each of these is an FTS5 syntax error when passed through unquoted.
    for query in ("Lunch.", "Lunch's", "Lunch-time", "Lunch & more"):
        assert isinstance(reader.search(query), list), query
    assert [item["subject"] for item in reader.search("Lunch.")] == ["Lunch"]
