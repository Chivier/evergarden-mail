from __future__ import annotations

import logging

import pytest
from test_archive_mail import FakeImap, _raw_message

from evergarden.archive.sqlite_archive import (
    ArchiveReader,
    ArchiveWriter,
    StaleMailboxSnapshot,
    open_readonly,
)
from evergarden.auth.credential_store import CredentialStore, generate_key
from evergarden.mail.models import AccountConfig
from evergarden.mail.sync import MailboxSyncIncomplete, ReadOnlyMailboxSync, parse_message


def setup_sync(tmp_path, fake):
    writer = ArchiveWriter(tmp_path / "archive")
    credentials = CredentialStore(tmp_path / "credentials.db", key=generate_key(), host_id="test")
    sync = ReadOnlyMailboxSync(
        archive=writer,
        credentials=credentials,
        oauth_access_token=lambda _account: "test-token",
        imap_factory=lambda *_args, **_kwargs: fake,
    )
    account = AccountConfig(
        alias="gmail",
        address="test@example.test",
        imap_host="imap.example.test",
        auth_kind="oauth2",
        folders=("INBOX",),
    )
    return writer, sync, account


@pytest.mark.parametrize("search", [b"", b"1"])
def test_incomplete_successful_search_cannot_tombstone_messages(tmp_path, search):
    class IncompleteSearch(FakeImap):
        def select(self, folder, readonly=False):
            self.calls.append(("select", folder, readonly))
            return "OK", [b"2"]

    fake = IncompleteSearch(_raw_message(), search=search)
    writer, sync, account = setup_sync(tmp_path, fake)
    record = parse_message(account="gmail", folder="INBOX", uid=2, raw=fake.raw, flags=())
    writer.upsert(record, uid_validity="777")
    writer.set_sync_state("gmail", "INBOX", "777", 2)
    before = ArchiveReader(writer.data_dir).message_locations(record.stable_id)
    with pytest.raises(MailboxSyncIncomplete, match="incomplete"):
        sync.sync_account(account)
    assert ArchiveReader(writer.data_dir).message_locations(record.stable_id) == before
    assert writer.sync_state("gmail", "INBOX") == ("777", 2)
    with open_readonly(writer.hot_path) as conn:
        assert conn.execute("SELECT count(*) FROM location_events").fetchone()[0] == 0
        assert conn.execute("SELECT status FROM sync_attempts").fetchone()[0] == "failed"


def test_discovered_deleted_folder_tracks_move_without_expanding_write_allowlist(tmp_path):
    class DiscoveredImap(FakeImap):
        selected = "INBOX"

        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\Trash) "/" "Deleted"',
                b'(\\Noselect) "/" "Parent"',
                b'(\\Sent) "/" "Sent"',
                b'(\\Drafts) "/" "Drafts"',
                b'(\\HasChildren) "/" "Calendar"',
            ]

        def select(self, folder, readonly=False):
            self.selected = str(folder).strip('"')
            self.search = b"50" if self.selected == "Deleted" else b""
            return super().select(folder, readonly=readonly)

    fake = DiscoveredImap(_raw_message())
    writer, sync, account = setup_sync(tmp_path, fake)
    record = parse_message(account="gmail", folder="INBOX", uid=11, raw=fake.raw, flags=())
    writer.upsert(record, uid_validity="777")
    writer.set_sync_state("gmail", "INBOX", "777", 11)
    writer.set_sync_state("gmail", "Deleted", "777", 100)
    result = sync.sync_account(account)
    assert set(result["folders"]) == {"INBOX", "Deleted"}
    assert result["folders"]["Deleted"]["historical_uid_discoveries"] == 1
    assert account.folders == ("INBOX",)
    assert account.safe_move_folders == ("Archive",)
    locations = ArchiveReader(writer.data_dir).message_locations(record.stable_id)
    assert [(row["folder"], row["uid"]) for row in locations] == [("Deleted", 50)]
    with open_readonly(writer.hot_path) as conn:
        assert (
            conn.execute("SELECT status FROM sync_attempts WHERE folder='Deleted'").fetchone()[0]
            == "ok"
        )
    assert all(call[-1] is True for call in fake.calls if call[0] == "select")
    assert not any(
        str(value).upper() in {"STORE", "MOVE", "COPY", "EXPUNGE", "DELETE"}
        for call in fake.calls
        for value in call
    )


def test_discovery_failure_is_reported_instead_of_silent_partial_coverage(tmp_path):
    class FailedList(FakeImap):
        def list(self):
            return "NO", []

    writer, sync, account = setup_sync(tmp_path, FailedList(_raw_message()))
    with pytest.raises(RuntimeError, match="LIST failed"):
        sync.sync_account(account)
    with open_readonly(writer.hot_path) as conn:
        assert conn.execute("SELECT status FROM sync_attempts").fetchone()[0] == "failed"


def test_read_folder_discovery_decodes_names_and_skips_unreadable_entries(caplog):
    account = AccountConfig(alias="gmail", address="test@example.test", imap_host="test")

    class Client:
        def list(self):
            return "OK", [b'(\\Junk) "/" "[Gmail]/Spam"', b'() "/" "&W1hoYw-"']

    assert ReadOnlyMailboxSync._read_folders(Client(), account) == ("INBOX", "[Gmail]/Spam", "存档")

    class BadClient:
        def list(self):
            return "OK", [
                b"invalid response",
                "not bytes",
                b'() "/" "\xff\xfe"',
                b'() "/" "&2D0-"',
                b'() "/" "Projects"',
            ]

    with caplog.at_level(logging.WARNING, logger="evergarden.mail.sync"):
        assert ReadOnlyMailboxSync._read_folders(BadClient(), account) == ("INBOX", "Projects")
    assert caplog.text.count("skipped unreadable LIST entry account=gmail") == 4


def test_unreadable_list_entry_is_skipped_while_other_folders_sync(tmp_path):
    class ListingImap(FakeImap):
        def list(self):
            return "OK", [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren) "/" "&2D0-"',
                b'(\\HasNoChildren) "/" "Projects"',
            ]

    fake = ListingImap(_raw_message(), search=b"")
    writer, sync, account = setup_sync(tmp_path, fake)
    result = sync.sync_account(account)
    assert set(result["folders"]) == {"INBOX", "Projects"}
    assert {folder["status"] for folder in result["folders"].values()} == {"ok"}
    with open_readonly(writer.hot_path) as conn:
        assert {row[0] for row in conn.execute("SELECT status FROM sync_attempts")} == {"ok"}


def test_snapshot_count_mismatch_on_first_read_is_retried(tmp_path):
    class ShortFirstSearch(FakeImap):
        searches = 0

        def uid(self, command, *args):
            if command == "SEARCH":
                self.searches += 1
                if self.searches == 1:
                    self.calls.append(("uid", command, *args))
                    return "OK", [b"10"]
            return super().uid(command, *args)

    fake = ShortFirstSearch(_raw_message(), search=b"10 11")
    writer, sync, account = setup_sync(tmp_path, fake)
    writer.upsert(
        parse_message(account="gmail", folder="INBOX", uid=10, raw=fake.raw, flags=()),
        uid_validity="777",
    )
    writer.set_sync_state("gmail", "INBOX", "777", 10)
    result = sync.sync_account(account)
    inbox = result["folders"]["INBOX"]
    assert inbox["status"] == "ok"
    assert inbox["snapshot_retries"] == 1
    assert inbox["fetched"] == 1
    assert writer.sync_state("gmail", "INBOX") == ("777", 11)
    assert fake.searches == 3


def test_inflight_snapshot_cannot_resurrect_a_newly_confirmed_move(tmp_path):
    class MovingDuringFetch(FakeImap):
        moved = False

        def uid(self, command, *args):
            response = super().uid(command, *args)
            if command == "FETCH" and args[0] == "1:*" and not self.moved:
                self.moved = True
                writer.confirm_move(
                    record.stable_id,
                    account="gmail",
                    source="INBOX",
                    destination="Archive",
                    destination_uid=8,
                    destination_uid_validity="888",
                )
                self.search = b""
            return response

    fake = MovingDuringFetch(_raw_message(), search=b"1")
    writer, sync, account = setup_sync(tmp_path, fake)
    record = parse_message(account="gmail", folder="INBOX", uid=1, raw=fake.raw, flags=())
    writer.upsert(record, uid_validity="777")
    writer.set_sync_state("gmail", "INBOX", "777", 1)
    sync.sync_account(account)
    reader = ArchiveReader(writer.data_dir)
    assert reader.message_context(record.stable_id)["folder"] == "Archive"
    assert [(row["folder"], row["uid"]) for row in reader.message_locations(record.stable_id)] == [
        ("Archive", 8)
    ]


def test_inflight_snapshot_cannot_undo_newer_provider_confirmed_flags(tmp_path):
    class MarkingDuringFetch(FakeImap):
        marked = False

        def uid(self, command, *args):
            response = super().uid(command, *args)
            if command == "FETCH" and args[0] == "1:*":
                if self.marked:
                    return "OK", [b"1 (UID 1 FLAGS ())"]
                self.marked = True
                writer.update_flags(record.stable_id, account="gmail", flags=())
            return response

    fake = MarkingDuringFetch(_raw_message(), search=b"1")
    writer, sync, account = setup_sync(tmp_path, fake)
    record = parse_message(account="gmail", folder="INBOX", uid=1, raw=fake.raw, flags=("\\Seen",))
    writer.upsert(record, uid_validity="777")
    writer.set_sync_state("gmail", "INBOX", "777", 1)
    sync.sync_account(account)
    reader = ArchiveReader(writer.data_dir)
    assert reader.message_context(record.stable_id)["flags"] == []
    assert reader.message_locations(record.stable_id)[0]["flags"] == []


def test_failed_folder_fetch_commits_neither_partial_locations_nor_watermark(tmp_path):
    class FailsSecondFetch(FakeImap):
        def uid(self, command, *args):
            if command == "FETCH" and args[0] == "2":
                return "NO", []
            return super().uid(command, *args)

    fake = FailsSecondFetch(_raw_message(), search=b"1 2")
    writer, sync, account = setup_sync(tmp_path, fake)
    writer.set_sync_state("gmail", "INBOX", "777", 0)
    with pytest.raises(MailboxSyncIncomplete):
        sync.sync_account(account)
    with open_readonly(writer.hot_path) as conn:
        assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM message_locations").fetchone()[0] == 0
    assert writer.sync_state("gmail", "INBOX") == ("777", 0)


def test_atomic_snapshot_rolls_back_new_mail_if_later_locator_verification_fails(tmp_path):
    import dataclasses

    writer, _sync, _account = setup_sync(tmp_path, FakeImap(_raw_message()))
    original = parse_message(account="gmail", folder="INBOX", uid=1, raw=_raw_message(), flags=())
    writer.upsert(original, uid_validity="777")
    writer.set_sync_state("gmail", "INBOX", "777", 1)
    first = parse_message(
        account="gmail",
        folder="INBOX",
        uid=2,
        raw=_raw_message(message_id="new@example.test"),
        flags=(),
    )
    # A different archived message claiming the UID the original already owns.
    other = parse_message(
        account="gmail",
        folder="Archive",
        uid=9,
        raw=_raw_message(message_id="other@example.test"),
        flags=(),
    )
    writer.upsert(other, uid_validity="archive-v")
    uid_thief = dataclasses.replace(other, folder="INBOX", uid=1)
    version = writer.state_version("gmail")
    with pytest.raises(RuntimeError, match="provider UID identity conflicts"):
        writer.apply_folder_snapshot(
            "gmail",
            "INBOX",
            "777",
            {1, 2},
            {1: (), 2: ()},
            [first, uid_thief],
            expected_version=version,
            last_uid=2,
        )
    assert not writer.has_message(first.stable_id, "gmail")
    assert writer.sync_state("gmail", "INBOX") == ("777", 1)
    assert writer.state_version("gmail") == version


def test_second_snapshot_from_same_version_cannot_overwrite_first_commit(tmp_path):
    writer, _sync, _account = setup_sync(tmp_path, FakeImap(_raw_message()))
    record = parse_message(account="gmail", folder="INBOX", uid=1, raw=_raw_message(), flags=())
    writer.upsert(record, uid_validity="777")
    writer.set_sync_state("gmail", "INBOX", "777", 1)
    version = writer.state_version("gmail")
    writer.apply_folder_snapshot(
        "gmail",
        "INBOX",
        "777",
        {1},
        {1: ("\\Seen",)},
        [],
        expected_version=version,
        last_uid=1,
    )
    with pytest.raises(StaleMailboxSnapshot):
        writer.apply_folder_snapshot(
            "gmail",
            "INBOX",
            "777",
            set(),
            {},
            [],
            expected_version=version,
            last_uid=0,
        )
    assert ArchiveReader(writer.data_dir).message_locations(record.stable_id)[0]["flags"] == [
        "\\Seen"
    ]
    assert writer.sync_state("gmail", "INBOX") == ("777", 1)
