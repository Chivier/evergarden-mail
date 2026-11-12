#!/usr/bin/env python3
"""Remove an explicitly selected, provider-audited cohort from local mail storage.

This maintenance command has no provider client and never changes PostgreSQL.
It requires a complete read-only provider inventory, locks all archive writers,
backs up every database, and verifies unrelated rows before committing. SQLite
WAL commits across files are not crash-atomic; the backup manifest records each
committed file so an interrupted operation can be investigated and restored.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
from collections import Counter
from contextlib import ExitStack, closing
from pathlib import Path

ARCHIVE_SCOPES = {
    "messages": "id",
    "message_locations": "stable_id",
    "provider_uid_observations": "stable_id",
    "provider_identity_verifications": "stable_id",
    "attachments": "message_id",
    "attachment_blobs": "message_id",
    "location_events": "stable_id",
}
FEEDBACK_SCOPES = {"issues": "stable_message_id", "issue_events": "issue_id"}


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        temporary.chmod(0o600)
        json.dump(value, stream, indent=2, sort_keys=True, default=str)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_cohort(path: Path) -> dict[str, str]:
    items = json.loads(path.read_text())["items"]
    result = {row["stable_message_id"]: row["account"] for row in items}
    if not result or len(result) != len(items):
        raise ValueError("cohort must contain unique message identities")
    if any(not re.fullmatch(r"[a-f0-9]{24}", mid) for mid in result):
        raise ValueError("invalid stable message identity")
    return result


def validate_audit(directory: Path, cohort: dict[str, str]) -> None:
    """Require a recent, exhaustive inventory for exactly the selected cohort."""
    summary = json.loads((directory / "summary.json").read_text())
    before = json.loads((directory / "before.json").read_text())
    if {row["id"]: row["account"] for row in before["targets"]} != cohort:
        raise ValueError("provider inventory covers a different cohort")
    account_counts = dict(Counter(cohort.values()))
    if (
        summary["started_target_count"] != len(cohort)
        or summary["target_counts_by_account"] != account_counts
        or summary["successful_accounts"] != len(account_counts)
        or summary["failed_accounts"]
        or summary["folder_errors"]
        or summary["candidate_messages"]
        or summary["verified_messages"]
        or summary["unreadable_after_fallback"]
        or summary["provider_mutations"] != 0
    ):
        raise ValueError("provider inventory is incomplete or contains possible matches")
    oldest = dt.datetime.now(dt.UTC).timestamp() - 3600
    for account, count in account_counts.items():
        # Account names become report filenames only after validation.
        if not re.fullmatch(r"[A-Za-z0-9_-]+", account):
            raise ValueError("invalid account alias")
        path = directory / f"{account}.json"
        report = json.loads(path.read_text())
        if path.stat().st_mtime < oldest:
            raise ValueError("provider inventory is older than one hour")
        if (
            report["account"] != account
            or report["target_count"] != count
            or report["errors"]
            or report["candidates"]
            or report["verified_matches"]
            or not report["listed_folders"]
            or set(report["listed_folders"]) != set(report["folders"])
            or set(report["provider_commands"]) - {"SEARCH", "FETCH", "SELECT_READONLY"}
        ):
            raise ValueError("provider account inventory is incomplete")
        for folder in report["folders"].values():
            if (
                folder["unreadable_uids"]
                or folder["candidate_count"]
                or folder["verified_count"]
                or folder["header_count"] + folder["full_body_fallbacks"] != folder["message_count"]
            ):
                raise ValueError("provider folder inventory is incomplete")


def archive_paths(directory: Path) -> list[Path]:
    hot = directory / "mail-hot.db"
    if not hot.is_file():
        raise ValueError("authoritative hot archive is required")
    years = sorted(directory.glob("mail-20[0-9][0-9].db"), reverse=True)
    paths = [hot, *years]
    for name in ("mail-unknown.db", "location-feedback.db"):
        if (directory / name).is_file():
            paths.append(directory / name)
    if any(path.is_symlink() for path in paths):
        raise ValueError("database symlinks are not supported")
    return paths


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")
        if not row[0].startswith(("messages_fts", "sqlite_"))
    }


def _prepare_scope(conn: sqlite3.Connection, cohort: dict[str, str], feedback: bool) -> None:
    conn.execute("CREATE TEMP TABLE cleanup_targets(id TEXT PRIMARY KEY, account TEXT)")
    conn.executemany("INSERT INTO cleanup_targets VALUES (?,?)", sorted(cohort.items()))
    if feedback:
        conn.execute(
            "CREATE TEMP TABLE cleanup_issues AS SELECT issue_id FROM issues "
            "WHERE stable_message_id IN (SELECT id FROM cleanup_targets)"
        )


def _predicate(table: str, feedback: bool) -> str:
    scopes = FEEDBACK_SCOPES if feedback else ARCHIVE_SCOPES
    column = scopes.get(table)
    if column is None:
        return "0"
    target = (
        "SELECT issue_id FROM cleanup_issues"
        if table == "issue_events"
        else ("SELECT id FROM cleanup_targets")
    )
    return f"{_quote(column)} IN ({target})"


def _counts(conn: sqlite3.Connection, feedback: bool) -> dict[str, int]:
    scopes = FEEDBACK_SCOPES if feedback else ARCHIVE_SCOPES
    return {
        table: conn.execute(
            f"SELECT count(*) FROM {_quote(table)} WHERE {_predicate(table, feedback)}"  # noqa: S608
        ).fetchone()[0]
        for table in sorted(_tables(conn) & scopes.keys())
    }


def _unrelated_fingerprints(conn: sqlite3.Connection, feedback: bool) -> dict:
    result = {}
    for table in sorted(_tables(conn) - {"mailbox_state_versions"}):
        digest = hashlib.sha256()
        count = 0
        for row in conn.execute(
            f"SELECT rowid,* FROM {_quote(table)} "  # noqa: S608
            f"WHERE ({_predicate(table, feedback)}) IS NOT TRUE ORDER BY rowid"
        ):
            encoded = json.dumps(
                list(row),
                separators=(",", ":"),
                default=lambda value: (
                    {"bytes": value.hex()} if isinstance(value, bytes) else str(value)
                ),
            ).encode()
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            count += 1
        result[table] = {"rows": count, "sha256": digest.hexdigest()}
    return result


def _check_unlocated(connections: list[tuple[Path, sqlite3.Connection]], cohort: dict) -> None:
    found = {}
    for path, conn in connections:
        if path.name == "location-feedback.db":
            continue
        for mid, account in conn.execute(
            "SELECT id,account FROM messages WHERE id IN (SELECT id FROM cleanup_targets)"
        ):
            if cohort[mid] != account:
                raise ValueError("archive account identity differs from the cohort")
            found[mid] = account
        if path.name == "mail-hot.db":
            for table in ("message_locations", "provider_uid_observations"):
                if (
                    table in _tables(conn)
                    and conn.execute(
                        f"SELECT 1 FROM {_quote(table)} WHERE active=1 "  # noqa: S608
                        "AND stable_id IN (SELECT id FROM cleanup_targets) LIMIT 1"
                    ).fetchone()
                ):
                    raise ValueError("a selected message has an active provider location")
    if found != cohort:
        raise ValueError("selected messages are missing from the archive; refusing partial cleanup")


def _fts_check(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO messages_fts(messages_fts,rank) VALUES('integrity-check',1)")


def plan_records(directory: Path, cohort: dict[str, str]) -> dict:
    with ExitStack() as stack:
        connections = []
        for path in archive_paths(directory):
            conn = stack.enter_context(
                closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True))
            )
            conn.execute("BEGIN")
            feedback = path.name == "location-feedback.db"
            _prepare_scope(conn, cohort, feedback)
            for table in _tables(conn):
                conn.execute(f"SELECT rowid FROM {_quote(table)} LIMIT 0")  # noqa: S608
            connections.append((path, conn))
        _check_unlocated(connections, cohort)
        return {
            path.name: _counts(conn, path.name == "location-feedback.db")
            for path, conn in connections
        }


def _versions(conn: sqlite3.Connection) -> dict[str, int]:
    if "mailbox_state_versions" not in _tables(conn):
        return {}
    return dict(conn.execute("SELECT account,version FROM mailbox_state_versions"))


def _delete_scoped_rows(conn: sqlite3.Connection, feedback: bool) -> None:
    if feedback:
        order = ("issue_events", "issues")
    else:
        # Older archive schemas have an FTS delete trigger; newer empty schemas
        # may not. Never remove the FTS document twice.
        has_fts_delete = any(
            "messages_fts" in row[0].lower()
            and re.search(r"\bafter\s+delete\s+on\s+[\"`\[]?messages\b", row[0], re.I)
            for row in conn.execute(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND tbl_name='messages'"
            )
        )
        if not has_fts_delete:
            rows = conn.execute(
                "SELECT rowid,subject,sender_name,body_text FROM messages "
                "WHERE id IN (SELECT id FROM cleanup_targets)"
            ).fetchall()
            conn.executemany(
                "INSERT INTO messages_fts(messages_fts,rowid,subject,sender_name,body_text) "
                "VALUES('delete',?,?,?,?)",
                rows,
            )
        order = (
            "attachment_blobs",
            "attachments",
            "provider_identity_verifications",
            "provider_uid_observations",
            "message_locations",
            "location_events",
            "messages",
        )
    for table in order:
        if table in _tables(conn):
            conn.execute(
                f"DELETE FROM {_quote(table)} WHERE {_predicate(table, feedback)}"  # noqa: S608
            )


def cleanup_records(
    directory: Path,
    cohort: dict[str, str],
    backup_dir: Path,
    *,
    evidence: dict | None = None,
    rebuild_inconsistent_fts: bool = False,
) -> dict:
    """Caller must validate provider evidence and check in-flight executions first."""
    paths = archive_paths(directory)
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {
        "started_at": dt.datetime.now(dt.UTC).isoformat(),
        "cohort_count": len(cohort),
        "account_counts": dict(Counter(cohort.values())),
        "status": "preflight",
        "databases": {},
        "committed": [],
        "provider_mutations": 0,
        "postgres_mutations": 0,
        "evidence": evidence or {},
    }
    write_json(
        backup_dir / "cohort.json",
        {
            "items": [
                {"stable_message_id": mid, "account": account}
                for mid, account in sorted(cohort.items())
            ]
        },
    )
    write_json(backup_dir / "manifest.json", manifest)
    with ExitStack() as stack:
        connections = []
        try:
            # Hot first matches rollover's lock order. Acquire every writer lock
            # before evidence checks, backup, or mutation so a sync cannot race.
            for path in paths:
                conn = stack.enter_context(closing(sqlite3.connect(path, timeout=30)))
                conn.execute("PRAGMA busy_timeout=30000")
                conn.execute("BEGIN IMMEDIATE")
                _prepare_scope(conn, cohort, path.name == "location-feedback.db")
                connections.append((path, conn))
            _check_unlocated(connections, cohort)
            for path, conn in connections:
                destination = backup_dir / path.name
                with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as src:
                    with closing(sqlite3.connect(destination)) as dst:
                        destination.chmod(0o600)
                        src.backup(dst)
                        if dst.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                            raise RuntimeError("backup failed SQLite integrity validation")
                with destination.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                feedback = path.name == "location-feedback.db"
                counts = _counts(conn, feedback)
                manifest["databases"][path.name] = {
                    "source": str(path),
                    "backup_sha256": digest,
                    "backup_bytes": destination.stat().st_size,
                    "removed": counts,
                    "unrelated_before": _unrelated_fingerprints(conn, feedback),
                }
                if "mailbox_state_versions" in _tables(conn):
                    expected = _versions(conn)
                    for table in ("message_locations", "provider_uid_observations"):
                        for account, count in conn.execute(
                            f"SELECT account,count(*) FROM {_quote(table)} "  # noqa: S608
                            "WHERE stable_id IN (SELECT id FROM cleanup_targets) GROUP BY account"
                        ):
                            expected[account] = expected.get(account, 0) + count
                    manifest["databases"][path.name]["versions_before"] = _versions(conn)
                    manifest["databases"][path.name]["versions_expected"] = expected
            manifest["status"] = "backed_up"
            write_json(backup_dir / "manifest.json", manifest)
            for path, conn in connections:
                info = manifest["databases"][path.name]
                if path.name == "location-feedback.db" or not info["removed"].get("messages"):
                    continue
                try:
                    _fts_check(conn)
                    info["fts_before"] = "consistent"
                except sqlite3.DatabaseError:
                    info["fts_before"] = "inconsistent"
                    if not rebuild_inconsistent_fts:
                        raise
                    if not conn.in_transaction:
                        raise RuntimeError("FTS error released the writer transaction") from None
                    # The index is derived entirely from canonical messages.
                    # Rebuild after all backups exist, inside the transaction
                    # used for deletion and the unrelated-row checks.
                    conn.execute("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')")
                    _fts_check(conn)
                    info["fts_rebuilt"] = True
            for path, conn in connections:
                feedback = path.name == "location-feedback.db"
                info = manifest["databases"][path.name]
                _delete_scoped_rows(conn, feedback)
                if any(_counts(conn, feedback).values()):
                    raise RuntimeError("selected rows remain after cleanup")
                info["unrelated_after"] = _unrelated_fingerprints(conn, feedback)
                if info["unrelated_before"] != info["unrelated_after"]:
                    raise RuntimeError("unrelated archive rows changed; rolling back")
                if "versions_expected" in info:
                    info["versions_after"] = _versions(conn)
                    if info["versions_after"] != info["versions_expected"]:
                        raise RuntimeError("mailbox version fencing failed; rolling back")
                if not feedback and info["removed"].get("messages"):
                    _fts_check(conn)
                if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError("cleaned database failed SQLite integrity validation")
            manifest["status"] = "verified_before_commit"
            write_json(backup_dir / "manifest.json", manifest)
            for path, conn in connections:
                conn.commit()
                manifest["committed"].append(path.name)
                write_json(backup_dir / "manifest.json", manifest)
            manifest["status"] = "complete"
            manifest["completed_at"] = dt.datetime.now(dt.UTC).isoformat()
            write_json(backup_dir / "manifest.json", manifest)
        except Exception:
            for _, conn in connections:
                conn.rollback()
            manifest["status"] = "interrupted" if manifest["committed"] else "rolled_back"
            write_json(backup_dir / "manifest.json", manifest)
            raise
    return manifest


def ledger_snapshot(settings, cohort: dict[str, str]) -> dict:
    """Read-only PostgreSQL signatures; encrypted payloads never leave memory."""
    import psycopg
    from psycopg.rows import dict_row

    from evergarden.approvals.service import PostgresApprovalRepository
    from evergarden.auth.credential_store import read_key_file

    repo = PostgresApprovalRepository(
        settings.database_url,
        key=read_key_file(settings.credential_key_file),
        host_id=settings.host_id,
    )
    with psycopg.connect(
        settings.database_url,
        row_factory=dict_row,
        connect_timeout=5,
        options="-c default_transaction_read_only=on -c statement_timeout=30000",
    ) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        drafts = [
            dict(row)
            for row in conn.execute("SELECT * FROM approval_drafts ORDER BY draft_id")
            if repo._decrypt(row).get("stable_message_id") in cohort
        ]
        draft_ids = [row["draft_id"] for row in drafts]
        approvals = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM approvals WHERE draft_id=ANY(%s) ORDER BY approval_id", (draft_ids,)
            )
        ]
        ledger = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM mail_action_ledger WHERE draft_id=ANY(%s) ORDER BY action_id",
                (draft_ids,),
            )
        ]
        all_executions = [
            dict(row) for row in conn.execute("SELECT * FROM mail_action_ledger ORDER BY action_id")
        ]
    if any(row["state"] == "ATTEMPTING" for row in ledger):
        raise ValueError("selected messages have in-flight executions")
    return {
        "draft_count": len(drafts),
        "approval_count": len(approvals),
        "execution_count": len(ledger),
        "execution_states": dict(Counter(row["state"] for row in ledger)),
        "global_execution_count": len(all_executions),
        "global_execution_states": dict(Counter(row["state"] for row in all_executions)),
        "global_execution_sha256": hashlib.sha256(
            json.dumps(all_executions, sort_keys=True, default=str).encode()
        ).hexdigest(),
        "sha256": hashlib.sha256(
            json.dumps([drafts, approvals, ledger], sort_keys=True, default=str).encode()
        ).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-file", type=Path, required=True)
    parser.add_argument("--audit-dir", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--rebuild-inconsistent-fts", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    from evergarden.config import get_settings

    settings = get_settings()
    cohort = load_cohort(args.cohort_file)
    validate_audit(args.audit_dir, cohort)
    before = ledger_snapshot(settings, cohort)
    if not args.apply:
        print(
            json.dumps(
                {
                    "cohort_count": len(cohort),
                    "audit": "complete",
                    "ledger": before,
                    "planned": plan_records(settings.archive_dir.resolve(), cohort),
                }
            )
        )
        return
    manifest = cleanup_records(
        settings.archive_dir.resolve(),
        cohort,
        args.backup_dir.resolve(),
        evidence={"audit_dir": str(args.audit_dir), "ledger_before": before},
        rebuild_inconsistent_fts=args.rebuild_inconsistent_fts,
    )
    write_json(args.backup_dir / "ledger-before.json", before)
    after = ledger_snapshot(settings, cohort)
    write_json(args.backup_dir / "ledger-after.json", after)
    if before != after:
        raise RuntimeError("PostgreSQL cohort changed concurrently; inspect ledger signatures")
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "cohort_count": len(cohort),
                "backup_dir": str(args.backup_dir),
                "ledger_unchanged": True,
                "removed": {name: info["removed"] for name, info in manifest["databases"].items()},
            }
        )
    )


if __name__ == "__main__":
    main()
