from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from deploy.scripts import cleanup_unlocated_mail as cleanup
from evergarden.archive.sqlite_archive import SCHEMA
from evergarden.mail.feedback import SCHEMA as FEEDBACK_SCHEMA

TARGET = "a" * 24
KEEP = "b" * 24
COHORT = {TARGET: "gmail"}


def _archives(root: Path, *, delete_trigger: bool = False) -> None:
    root.mkdir()
    for name in ("mail-hot.db", "mail-2026.db"):
        with closing(sqlite3.connect(root / name)) as conn:
            conn.executescript(SCHEMA)
            if delete_trigger:
                conn.executescript("""
                    CREATE TRIGGER messages_ad AFTER DELETE ON messages BEGIN
                    INSERT INTO messages_fts(messages_fts,rowid,subject,sender_name,body_text)
                    VALUES('delete',old.rowid,old.subject,old.sender_name,old.body_text);
                    END;
                """)
            for mid, text in ((KEEP, "unrelatedsurvivor"), (TARGET, "ghostuniqueterm")):
                conn.execute(
                    "INSERT INTO messages(id,account,subject,body_text) VALUES (?,?,?,?)",
                    (mid, "gmail", text, text),
                )
                # Active yearly rows are historical; only the hot DB is authoritative.
                active = int(mid == KEEP or name != "mail-hot.db")
                conn.execute(
                    "INSERT INTO message_locations(stable_id,account,folder,uid,"
                    "uid_validity,active,observed_at) VALUES (?,?,'INBOX',1,'v1',?,'now')",
                    (mid, "gmail", active),
                )
                conn.execute(
                    "INSERT INTO provider_uid_observations(account,folder,uid_validity,uid,"
                    "stable_id,active,observed_at) VALUES ('gmail','INBOX','v1',?,?,?,'now')",
                    (1 if mid == KEEP else 2, mid, active),
                )
                conn.execute(
                    "INSERT INTO attachments VALUES (?,?,?,'text/plain',1)", (mid, mid, text)
                )
                conn.execute(
                    "INSERT INTO attachment_blobs VALUES (?,?,X'01',X'02','hash',1,'now')",
                    (mid, mid),
                )
            conn.commit()
    with closing(sqlite3.connect(root / "location-feedback.db")) as conn:
        conn.executescript(FEEDBACK_SCHEMA)
        for mid in (KEEP, TARGET):
            conn.execute(
                "INSERT INTO issues VALUES (?,?,'missing','archive','pending','blocked','now',"
                "'now','diagnostic')",
                (mid, mid),
            )
            conn.execute(
                "INSERT INTO issue_events(issue_id,recorded_at,event_json) VALUES (?,'now','{}')",
                (mid,),
            )
        conn.commit()


@pytest.mark.parametrize("delete_trigger", [False, True])
def test_cleanup_removes_all_copies_and_fts_without_affecting_other_mail(
    tmp_path: Path,
    delete_trigger: bool,
) -> None:
    root = tmp_path / "archive"
    _archives(root, delete_trigger=delete_trigger)
    backup = tmp_path / "backup"
    result = cleanup.cleanup_records(root, COHORT, backup)
    assert result["status"] == "complete"
    assert len(result["committed"]) == 3
    for name in ("mail-hot.db", "mail-2026.db"):
        with closing(sqlite3.connect(root / name)) as conn:
            assert conn.execute("SELECT id FROM messages").fetchall() == [(KEEP,)]
            assert conn.execute("SELECT id FROM attachments").fetchall() == [(KEEP,)]
            assert conn.execute("SELECT attachment_id FROM attachment_blobs").fetchall() == [
                (KEEP,)
            ]
            assert conn.execute("SELECT stable_id FROM message_locations").fetchall() == [(KEEP,)]
            assert conn.execute("SELECT stable_id FROM provider_uid_observations").fetchall() == [
                (KEEP,)
            ]
            # ROWID reuse must not give new mail a deleted message's search terms.
            conn.execute(
                "INSERT INTO messages(id,account,subject,body_text) VALUES ('new','gmail','new','new')"
            )
            assert conn.execute("SELECT rowid FROM messages WHERE id='new'").fetchone()[0] == 2
            assert not conn.execute(
                "SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'ghostuniqueterm'"
            ).fetchall()
            cleanup._fts_check(conn)
        with closing(sqlite3.connect(backup / name)) as conn:
            assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 2
            cleanup._fts_check(conn)
        info = result["databases"][name]
        assert info["unrelated_before"] == info["unrelated_after"]
        assert (backup / name).stat().st_mode & 0o077 == 0
    with closing(sqlite3.connect(root / "location-feedback.db")) as conn:
        assert conn.execute("SELECT stable_message_id FROM issues").fetchall() == [(KEEP,)]
        assert conn.execute("SELECT issue_id FROM issue_events").fetchall() == [(KEEP,)]


@pytest.mark.parametrize("table", ["message_locations", "provider_uid_observations"])
def test_cleanup_refuses_a_message_that_has_reappeared(tmp_path: Path, table: str) -> None:
    root = tmp_path / "archive"
    _archives(root)
    with closing(sqlite3.connect(root / "mail-hot.db")) as conn:
        conn.execute(f"UPDATE {table} SET active=1 WHERE stable_id=?", (TARGET,))  # noqa: S608
        conn.commit()
    with pytest.raises(ValueError, match="active provider location"):
        cleanup.cleanup_records(root, COHORT, tmp_path / "backup")
    with closing(sqlite3.connect(root / "mail-hot.db")) as conn:
        assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 2


def test_cleanup_rolls_back_all_shards_when_later_mutation_fails(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "archive"
    _archives(root)
    original = cleanup._delete_scoped_rows
    calls = []

    def fail_later(conn, feedback):
        calls.append(True)
        if len(calls) == 2:
            raise RuntimeError("injected failure after hot deletion")
        original(conn, feedback)

    monkeypatch.setattr(cleanup, "_delete_scoped_rows", fail_later)
    backup = tmp_path / "backup"
    with pytest.raises(RuntimeError, match="injected failure"):
        cleanup.cleanup_records(root, COHORT, backup)
    manifest = json.loads((backup / "manifest.json").read_text())
    assert manifest["status"] == "rolled_back"
    assert not manifest["committed"]
    for name in ("mail-hot.db", "mail-2026.db"):
        with closing(sqlite3.connect(root / name)) as conn:
            assert conn.execute("SELECT count(*) FROM messages").fetchone()[0] == 2
            assert (
                conn.execute(
                    "SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'ghostuniqueterm'"
                ).fetchone()[0]
                == 1
            )
            cleanup._fts_check(conn)


def test_cleanup_can_rebuild_a_preexisting_stale_index_after_backup(tmp_path: Path) -> None:
    root = tmp_path / "archive"
    _archives(root)
    with closing(sqlite3.connect(root / "mail-2026.db")) as conn:
        conn.execute(
            "INSERT INTO messages_fts(messages_fts,rowid,subject,sender_name,body_text) "
            "VALUES('delete',1,'unrelatedsurvivor',NULL,'unrelatedsurvivor')"
        )
        conn.commit()
    with pytest.raises(sqlite3.DatabaseError):
        cleanup.cleanup_records(root, COHORT, tmp_path / "refused-backup")
    result = cleanup.cleanup_records(
        root,
        COHORT,
        tmp_path / "backup",
        rebuild_inconsistent_fts=True,
    )
    assert result["databases"]["mail-2026.db"]["fts_rebuilt"] is True
    assert "fts_rebuilt" not in result["databases"]["mail-hot.db"]
    with closing(sqlite3.connect(root / "mail-2026.db")) as conn:
        cleanup._fts_check(conn)
        assert conn.execute(
            "SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'unrelatedsurvivor'"
        ).fetchall() == [(1,)]
        assert conn.execute("SELECT id FROM messages").fetchall() == [(KEEP,)]


def test_provider_audit_requires_complete_exact_cohort_and_no_matches(tmp_path: Path) -> None:
    cleanup.write_json(tmp_path / "before.json", {"targets": [{"id": TARGET, "account": "gmail"}]})
    summary = {
        "started_target_count": 1,
        "target_counts_by_account": {"gmail": 1},
        "successful_accounts": 1,
        "failed_accounts": [],
        "folder_errors": [],
        "candidate_messages": 0,
        "verified_messages": 0,
        "unreadable_after_fallback": 0,
        "provider_mutations": 0,
    }
    cleanup.write_json(tmp_path / "summary.json", summary)
    account = {
        "account": "gmail",
        "target_count": 1,
        "errors": [],
        "candidates": {},
        "verified_matches": {},
        "listed_folders": ["INBOX"],
        "provider_commands": {"SEARCH": 2, "FETCH": 1, "SELECT_READONLY": 1},
        "folders": {
            "INBOX": {
                "message_count": 2,
                "header_count": 1,
                "full_body_fallbacks": 1,
                "unreadable_uids": [],
                "candidate_count": 0,
                "verified_count": 0,
            }
        },
    }
    cleanup.write_json(tmp_path / "gmail.json", account)
    cleanup.validate_audit(tmp_path, COHORT)
    with pytest.raises(ValueError, match="different cohort"):
        cleanup.validate_audit(tmp_path, {KEEP: "gmail"})
    account["folders"]["INBOX"]["full_body_fallbacks"] = 0
    cleanup.write_json(tmp_path / "gmail.json", account)
    with pytest.raises(ValueError, match="folder inventory is incomplete"):
        cleanup.validate_audit(tmp_path, COHORT)
    account["folders"]["INBOX"]["full_body_fallbacks"] = 1
    account["candidates"] = {TARGET: [{"uid": 123}]}
    cleanup.write_json(tmp_path / "gmail.json", account)
    with pytest.raises(ValueError, match="account inventory is incomplete"):
        cleanup.validate_audit(tmp_path, COHORT)
