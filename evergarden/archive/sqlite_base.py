"""Shared SQLite schema, hardening, attachment crypto and location reconciliation."""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import sqlite3
import stat
from collections.abc import Mapping, Sequence
from email.utils import getaddresses
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from evergarden.mail.models import MessageRecord, normalize_message_id
from evergarden.mail.parse import html_to_text

LOGGER = logging.getLogger(__name__)

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    account TEXT NOT NULL,
    folder TEXT,
    uid INTEGER,
    message_id TEXT,
    reply_to TEXT,
    in_reply_to TEXT,
    references_ids TEXT,
    sender_raw TEXT,
    sender_name TEXT,
    sender_email TEXT,
    recipients_to TEXT,
    recipients_cc TEXT,
    recipients_bcc TEXT,
    list_id TEXT,
    subject TEXT,
    date_received TEXT,
    body_text TEXT,
    body_html TEXT,
    has_attachments INTEGER DEFAULT 0,
    flags TEXT,
    raw_size INTEGER,
    body_fetched INTEGER DEFAULT 0,
    raw_body_sha256 TEXT,
    fetched_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_account_folder ON messages(account, folder);
CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date_received);
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id);
CREATE INDEX IF NOT EXISTS idx_messages_location_metadata ON messages(
    id,account,folder,sender_name,sender_email,recipients_to,recipients_cc,
    subject,date_received,has_attachments,flags,uid,raw_body_sha256,updated_at
);
CREATE TABLE IF NOT EXISTS message_locations (
    stable_id TEXT NOT NULL,
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid INTEGER NOT NULL,
    uid_validity TEXT NOT NULL DEFAULT '',
    flags TEXT NOT NULL DEFAULT '[]',
    raw_body_sha256 TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    observed_at TEXT NOT NULL,
    PRIMARY KEY(stable_id,account,folder)
);
CREATE INDEX IF NOT EXISTS idx_message_locations_account_folder
ON message_locations(account,folder,active);
CREATE TABLE IF NOT EXISTS provider_uid_observations (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid_validity TEXT NOT NULL,
    uid INTEGER NOT NULL,
    stable_id TEXT NOT NULL,
    flags TEXT NOT NULL DEFAULT '[]',
    raw_body_sha256 TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    observed_at TEXT NOT NULL,
    PRIMARY KEY(account,folder,uid_validity,uid)
);
CREATE INDEX IF NOT EXISTS idx_provider_uid_observations_message
ON provider_uid_observations(stable_id,account,folder,active);
CREATE TABLE IF NOT EXISTS provider_identity_verifications (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid_validity TEXT NOT NULL,
    uid INTEGER NOT NULL,
    stable_id TEXT NOT NULL,
    provider_raw_body_sha256 TEXT NOT NULL,
    archive_raw_body_sha256 TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    PRIMARY KEY(account,folder,uid_validity,uid)
);
CREATE TABLE IF NOT EXISTS provider_identity_conflicts (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid_validity TEXT NOT NULL,
    uid INTEGER NOT NULL,
    stable_id TEXT NOT NULL,
    provider_raw_body_sha256 TEXT NOT NULL,
    archive_raw_body_sha256 TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    cleared_at TEXT,
    PRIMARY KEY(account,folder,uid_validity,uid)
);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    subject, sender_name, body_text, content='messages', content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts(rowid,subject,sender_name,body_text)
  VALUES(new.rowid,new.subject,new.sender_name,new.body_text);
END;
CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts,rowid,subject,sender_name,body_text)
  VALUES('delete',old.rowid,old.subject,old.sender_name,old.body_text);
  INSERT INTO messages_fts(rowid,subject,sender_name,body_text)
  VALUES(new.rowid,new.subject,new.sender_name,new.body_text);
END;
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    filename TEXT,
    mimetype TEXT,
    size INTEGER
);
CREATE TABLE IF NOT EXISTS attachment_blobs (
    attachment_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    content_sha256 TEXT NOT NULL,
    content_size INTEGER NOT NULL,
    stored_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shadow_sync_state (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid_validity TEXT NOT NULL,
    last_uid INTEGER NOT NULL DEFAULT 0,
    last_synced_at TEXT NOT NULL,
    PRIMARY KEY(account,folder)
);
CREATE TABLE IF NOT EXISTS shadow_rollover_ledger (
    scheduled_slot TEXT PRIMARY KEY,
    cutoff TEXT NOT NULL,
    copied_count INTEGER NOT NULL,
    source_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS archive_schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS location_events (
    event_id INTEGER PRIMARY KEY,
    stable_id TEXT NOT NULL,
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_location_events_message ON location_events(stable_id,event_id);
CREATE TABLE IF NOT EXISTS sync_attempts (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    sync_run_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason_code TEXT,
    attempted_at TEXT NOT NULL,
    PRIMARY KEY(account,folder)
);
CREATE TABLE IF NOT EXISTS sync_attempt_order (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    started_at TEXT NOT NULL,
    PRIMARY KEY(account,folder)
);
CREATE TABLE IF NOT EXISTS mailbox_state_versions (
    account TEXT PRIMARY KEY,
    version INTEGER NOT NULL
);
"""

# Track every locator writer, including older services and metadata repairs.
# A provider snapshot may be committed only if its account has not changed
# since the read began. The version check and all writes share one transaction.
for _version_table in ("message_locations", "provider_uid_observations", "shadow_sync_state"):
    for _version_event in ("INSERT", "UPDATE", "DELETE"):
        _version_row = "OLD" if _version_event == "DELETE" else "NEW"
        SCHEMA += f"""
CREATE TRIGGER IF NOT EXISTS state_version_{_version_table}_{_version_event.lower()}
AFTER {_version_event} ON {_version_table} BEGIN
  INSERT INTO mailbox_state_versions(account,version) VALUES ({_version_row}.account,1)
  ON CONFLICT(account) DO UPDATE SET version=version+1;
END;
"""  # noqa: S608 - only fixed table, event and row names above

PUBLIC_MESSAGE_COLUMNS_SQL = (
    "id,account,folder,sender_name,sender_email,recipients_to,recipients_cc,"
    "subject,date_received,has_attachments,flags"
)


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds")


def _utc_boundary(value: str) -> str:
    """Normalize a caller's ISO instant to the stored UTC text form.

    Stored `date_received` is always UTC rendered with a `+00:00` suffix, and
    every range filter compares against it lexicographically. A boundary
    carrying any other offset must be converted first: comparing
    "2026-08-27T00:00:00+01:00" as text silently filters an hour away from the
    instant the caller asked for. A naive value is read as UTC, which is what
    a bare "2026-08-27" date has always meant here.
    """
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC).isoformat(timespec="seconds")


def _is_plausible_date(value: object) -> bool:
    """Reject empty and absurd stored dates before they lead a comparison."""
    text = str(value or "")
    if not text:
        return False
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    return 1990 <= parsed.year <= dt.datetime.now(dt.UTC).year + 1


def _normalized_reference_ids(value: object) -> tuple[str, ...]:
    raw = str(value or "")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    values = parsed if isinstance(parsed, list) else re.findall(r"<([^>]+)>", raw)
    if not isinstance(parsed, list) and not values and raw:
        values = raw.split()
    return tuple(
        sorted(normalized for item in values if (normalized := normalize_message_id(str(item))))
    )


def _mailboxes_are_provider_equivalent(left: object, right: object) -> bool:
    left_text, right_text = str(left or ""), str(right or "")
    if left_text == right_text:
        return True
    if not left_text or not right_text:
        return False
    parsed = [getaddresses([value]) for value in (left_text, right_text)]
    if any(
        not addresses
        or any(not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+", address) for _, address in addresses)
        for addresses in parsed
    ):
        return False
    return sorted(address.casefold() for _, address in parsed[0]) == sorted(
        address.casefold() for _, address in parsed[1]
    )


def _dates_are_provider_equivalent(left: object, right: object) -> bool:
    left_text = str(left or "")
    right_text = str(right or "")
    if left_text == right_text:
        return True
    if not left_text or not right_text:
        return False
    try:
        left_date = dt.datetime.fromisoformat(left_text.replace("Z", "+00:00"))
        right_date = dt.datetime.fromisoformat(right_text.replace("Z", "+00:00"))
    except ValueError:
        return False
    left_date = left_date.replace(tzinfo=left_date.tzinfo or dt.UTC).astimezone(dt.UTC)
    right_date = right_date.replace(tzinfo=right_date.tzinfo or dt.UTC).astimezone(dt.UTC)
    return abs(left_date - right_date) <= dt.timedelta(minutes=5)


def _reconcile_logical_locations(
    conn: sqlite3.Connection,
    *,
    stable_id: str | None = None,
    account: str | None = None,
    prefer_config_order: bool = False,
    folder_precedence: Mapping[str, Sequence[str]] | None = None,
) -> int:
    """Choose each message's logical folder among its active provider locations.

    The current folder stays while it is still active. Otherwise, or when
    ``prefer_config_order`` asks for it, the account's configured folder
    precedence decides (see ``AccountConfig.folder_precedence``), with name
    order as the deterministic fallback for unconfigured folders.
    """
    if stable_id is not None and account is not None:
        messages = conn.execute(
            "SELECT id,account,folder,uid,flags FROM messages WHERE id=? AND account=?",
            (stable_id, account),
        ).fetchall()
    else:
        messages = conn.execute("SELECT id,account,folder,uid,flags FROM messages").fetchall()
    updated = 0
    for message in messages:
        locations = conn.execute(
            "SELECT folder,uid,flags FROM message_locations "
            "WHERE stable_id=? AND account=? AND active=1",
            (message["id"], message["account"]),
        ).fetchall()
        if not locations:
            continue
        by_folder = {str(row["folder"]): row for row in locations}
        current_folder = str(message["folder"] or "")
        if current_folder in by_folder and not prefer_config_order:
            chosen = by_folder[current_folder]
        else:
            order = (folder_precedence or {}).get(str(message["account"]), ())
            preferred = next((folder for folder in order if folder in by_folder), None)
            chosen = by_folder[preferred] if preferred else by_folder[sorted(by_folder)[0]]
        if (
            current_folder != str(chosen["folder"])
            or int(message["uid"] or 0) != int(chosen["uid"])
            or str(message["flags"] or "[]") != str(chosen["flags"] or "[]")
        ):
            conn.execute(
                "UPDATE messages SET folder=?,uid=?,flags=?,updated_at=? WHERE id=? AND account=?",
                (
                    str(chosen["folder"]),
                    int(chosen["uid"]),
                    str(chosen["flags"] or "[]"),
                    _utc_now(),
                    str(message["id"]),
                    str(message["account"]),
                ),
            )
            updated += 1
    return updated


def _private_sqlite_path(path: Path, *, writable: bool) -> None:
    if path.parent.is_symlink() or path.is_symlink():
        raise RuntimeError("mail archive path must not be a symlink")
    if writable:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.chmod(0o700)
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("mail archive shard must be a regular file")
        if writable:
            path.chmod(0o600)
        elif info.st_mode & 0o077:
            raise RuntimeError("mail archive shard must be mode 0600")


def _harden_sqlite_files(path: Path) -> None:
    path.chmod(0o600)
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists() and not sidecar.is_symlink():
            sidecar.chmod(0o600)


def open_writer(path: Path) -> sqlite3.Connection:
    _private_sqlite_path(path, writable=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    _harden_sqlite_files(path)
    conn.executescript(SCHEMA)
    # Serialize every check-then-alter/backfill below: MCP, worker, and the
    # bridge open writers independently, and two concurrent first opens would
    # otherwise both see "column missing"/"not migrated" and the loser would
    # crash on the duplicate ALTER or the UNIQUE migration insert.
    conn.execute("BEGIN IMMEDIATE")
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(messages)")}
    if "reply_to" not in columns:
        conn.execute("ALTER TABLE messages ADD COLUMN reply_to TEXT")
    location_migration = "002_message_locations"
    migrated = conn.execute(
        "SELECT 1 FROM archive_schema_migrations WHERE name=?", (location_migration,)
    ).fetchone()
    if not migrated:
        now = _utc_now()
        conn.execute(
            """
            INSERT OR IGNORE INTO message_locations(
              stable_id,account,folder,uid,uid_validity,flags,raw_body_sha256,
              active,observed_at
            )
            SELECT id,account,folder,uid,
              COALESCE((
                SELECT uid_validity FROM shadow_sync_state s
                WHERE s.account=messages.account AND s.folder=messages.folder
              ),''),
              COALESCE(flags,'[]'),COALESCE(raw_body_sha256,''),1,
              COALESCE(updated_at,fetched_at,?)
            FROM messages
            WHERE folder IS NOT NULL AND folder<>'' AND uid IS NOT NULL AND uid>0
            """,
            (now,),
        )
        conn.execute(
            "INSERT INTO archive_schema_migrations(name,applied_at) VALUES (?,?)",
            (location_migration, now),
        )
    html_body_migration = "003_html_only_body_text"
    migrated = conn.execute(
        "SELECT 1 FROM archive_schema_migrations WHERE name=?", (html_body_migration,)
    ).fetchone()
    if not migrated:
        for message_id, body_html in conn.execute(
            "SELECT id,body_html FROM messages "
            "WHERE trim(COALESCE(body_text,''))='' AND COALESCE(body_html,'')<>''"
        ).fetchall():
            body_text = html_to_text(str(body_html))
            if body_text:
                conn.execute(
                    "UPDATE messages SET body_text=? WHERE id=?",
                    (body_text, str(message_id)),
                )
        conn.execute(
            "INSERT INTO archive_schema_migrations(name,applied_at) VALUES (?,?)",
            (html_body_migration, _utc_now()),
        )
    canonical_location_migration = "004_canonical_logical_location"
    migrated = conn.execute(
        "SELECT 1 FROM archive_schema_migrations WHERE name=?",
        (canonical_location_migration,),
    ).fetchone()
    if not migrated:
        # The imported logical folder is authoritative while that provider
        # location is still active.  Configured folder order is only a
        # deterministic fallback after the authoritative location disappears.
        _reconcile_logical_locations(conn)
        conn.execute(
            "INSERT INTO archive_schema_migrations(name,applied_at) VALUES (?,?)",
            (canonical_location_migration, _utc_now()),
        )
    provider_uid_migration = "005_provider_uid_observations"
    migrated = conn.execute(
        "SELECT 1 FROM archive_schema_migrations WHERE name=?",
        (provider_uid_migration,),
    ).fetchone()
    if not migrated:
        conn.execute(
            """
            INSERT OR IGNORE INTO provider_uid_observations(
              account,folder,uid_validity,uid,stable_id,flags,
              raw_body_sha256,active,observed_at
            )
            SELECT account,folder,uid_validity,uid,stable_id,flags,
                   raw_body_sha256,active,observed_at
            FROM message_locations
            WHERE uid>0
            """
        )
        conn.execute(
            "INSERT INTO archive_schema_migrations(name,applied_at) VALUES (?,?)",
            (provider_uid_migration, _utc_now()),
        )
    conn.commit()
    return conn


def open_readonly(path: Path) -> sqlite3.Connection:
    _private_sqlite_path(path, writable=False)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _attachment_cipher(master_key: bytes | None) -> AESGCM | None:
    if master_key is None:
        return None
    if len(master_key) != 32:
        raise ValueError("attachment encryption requires a 32-byte master key")
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"evergarden:attachment:v1",
    ).derive(master_key)
    return AESGCM(key)


def _attachment_aad(attachment_id: str, message_id: str, mimetype: str, size: int) -> bytes:
    return f"evergarden:attachment:v1:{attachment_id}:{message_id}:{mimetype}:{size}".encode()


class StaleMailboxSnapshot(RuntimeError):
    """Newer mailbox evidence superseded an in-flight read-only snapshot."""


class ProviderIdentityConflict(RuntimeError):
    """A provider copy shares a stable identity but not the archived content."""

    def __init__(self, record: MessageRecord, archive_raw_body_sha256: str):
        super().__init__(
            "provider location body identity conflicts with archive message "
            f"stable_id={record.stable_id} account={record.account} uid={record.uid}"
        )
        self.record = record
        self.archive_raw_body_sha256 = archive_raw_body_sha256
