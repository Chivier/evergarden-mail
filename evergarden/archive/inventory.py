"""Content-free inventory of the local mail archive (the cold-export job)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from contextlib import closing
from pathlib import Path
from typing import Any

from evergarden.archive.sqlite_archive import open_readonly
from evergarden.mail.inventory import inventory_row_from_mapping

# Version 4 carries mail inventory evidence only: stable ids, hashed message
# ids, normalized dates, fingerprints and sizes, never subjects or bodies.
INVENTORY_VERSION = 4
INVENTORY_SCOPE = "mail-only"


def _inventory_messages_sha256(messages: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        json.dumps(messages, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _archive_paths(data_dir: Path) -> list[Path]:
    names = [data_dir / "mail-hot.db"]
    names.extend(sorted(data_dir.glob("mail-[0-9][0-9][0-9][0-9].db")))
    names.append(data_dir / "mail-unknown.db")
    return [path for path in names if path.is_file()]


def build_inventory(
    data_dir: Path,
    *,
    source_host: str,
    snapshot_tag: str,
    generated_at: dt.datetime | None = None,
) -> dict[str, Any]:
    records: dict[str, dict[str, str | int]] = {}
    shard_integrity: dict[str, str] = {}
    for path in _archive_paths(data_dir):
        with closing(open_readonly(path)) as conn:
            shard_integrity[path.name] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
            for row in conn.execute(
                "SELECT id,account,folder,message_id,date_received,sender_email,subject,raw_size "
                "FROM messages"
            ):
                stable_id = str(row["id"])
                records.setdefault(stable_id, inventory_row_from_mapping(row))
    ordered = [records[key] for key in sorted(records)]
    timestamp = generated_at or dt.datetime.now(dt.UTC)
    if timestamp.tzinfo is None:
        raise ValueError("inventory generation timestamp must include a timezone")
    return {
        "version": INVENTORY_VERSION,
        "scope": INVENTORY_SCOPE,
        "source_host": source_host,
        "snapshot_tag": snapshot_tag,
        "generated_at": timestamp.astimezone(dt.UTC).isoformat(timespec="seconds"),
        "message_count": len(ordered),
        "inventory_sha256": _inventory_messages_sha256(ordered),
        "shard_integrity": shard_integrity,
        "messages": ordered,
    }
