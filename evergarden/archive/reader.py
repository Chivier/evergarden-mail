"""Read-only archive queries over the hot database and year shards."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from evergarden.archive.sqlite_base import (
    PUBLIC_MESSAGE_COLUMNS_SQL,
    _attachment_aad,
    _attachment_cipher,
    _is_plausible_date,
    _utc_boundary,
    _utc_now,
    open_readonly,
)
from evergarden.audit.redaction import redact_text
from evergarden.mail.attachments import MAX_DOWNLOAD_BYTES, safe_filename, validate_download
from evergarden.mail.models import normalize_message_id


def _literal_fts_query(query: str) -> str:
    """Quote each whitespace-separated word so FTS5 treats it as plain text."""
    return " ".join('"' + word.replace('"', '""') + '"' for word in query.split())


class ArchiveReader:
    def __init__(
        self,
        data_dir: Path,
        *,
        max_limit: int = 100,
        max_body_chars: int = 30000,
        attachment_key: bytes | None = None,
    ):
        self.data_dir = data_dir
        self.max_limit = max_limit
        self.max_body_chars = max_body_chars
        self._attachment_cipher = _attachment_cipher(attachment_key)

    def paths(self) -> list[Path]:
        paths: list[Path] = []
        hot = self.data_dir / "mail-hot.db"
        if hot.is_file():
            paths.append(hot)
        paths.extend(sorted(self.data_dir.glob("mail-[0-9][0-9][0-9][0-9].db"), reverse=True))
        unknown = self.data_dir / "mail-unknown.db"
        if unknown.is_file():
            paths.append(unknown)
        return paths

    def _limit(self, limit: int) -> int:
        return max(1, min(int(limit), self.max_limit))

    def _collect(
        self,
        sql: str,
        params: list[Any],
        limit: int,
        *,
        required_table: str | None = None,
    ) -> list[sqlite3.Row]:
        by_id: dict[str, sqlite3.Row] = {}
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                if (
                    required_table is not None
                    and not conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?",
                        (required_table,),
                    ).fetchone()
                ):
                    continue
                for row in conn.execute(sql, [*params, limit]).fetchall():
                    by_id.setdefault(str(row["id"]), row)
        return sorted(by_id.values(), key=lambda row: row["date_received"] or "", reverse=True)[
            :limit
        ]

    def list_recent(
        self,
        *,
        account: str | None = None,
        folder: str | None = None,
        inbox_only: bool = False,
        since: str | None = None,
        before: str | None = None,
        unread_only: bool = False,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if account:
            clauses.append("account=?")
            params.append(account)
        if folder:
            clauses.append("folder=?")
            params.append(folder)
        if inbox_only:
            clauses.append("folder COLLATE NOCASE='INBOX'")
        if since:
            clauses.append("date_received>=?")
            params.append(_utc_boundary(since))
        if before:
            clauses.append("date_received<?")
            params.append(_utc_boundary(before))
        if unread_only:
            # Flags are stored JSON-encoded, so \Seen appears as \\Seen on disk.
            clauses.append("(flags IS NULL OR flags NOT LIKE '%\\\\Seen%')")
        where = " AND ".join(clauses) or "1=1"
        bounded = self._limit(limit)
        # `where` is assembled only from fixed clauses above; values are parameters.
        rows = self._collect(
            f"SELECT {PUBLIC_MESSAGE_COLUMNS_SQL} FROM messages "  # noqa: S608
            f"WHERE {where} ORDER BY date_received DESC LIMIT ?",
            params,
            bounded,
        )
        return [self._public(row) for row in rows]

    def count_messages(
        self,
        *,
        account: str | None = None,
        folder: str | None = None,
        inbox_only: bool = False,
        since: str | None = None,
        before: str | None = None,
        unread_only: bool = False,
    ) -> int:
        """Count unique archived messages with the same filters as list_recent."""
        clauses: list[str] = []
        params: list[Any] = []
        if account:
            clauses.append("account=?")
            params.append(account)
        if folder:
            clauses.append("folder=?")
            params.append(folder)
        if inbox_only:
            clauses.append("folder COLLATE NOCASE='INBOX'")
        if since:
            clauses.append("date_received>=?")
            params.append(_utc_boundary(since))
        if before:
            clauses.append("date_received<?")
            params.append(_utc_boundary(before))
        if unread_only:
            # Flags are stored JSON-encoded, so \Seen appears as \\Seen on
            # disk; keep this pattern identical to list_recent.
            clauses.append("(flags IS NULL OR flags NOT LIKE '%\\\\Seen%')")
        where = " AND ".join(clauses) or "1=1"
        seen: set[str] = set()
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                # `where` contains fixed clauses only; values remain parameterized.
                seen.update(
                    str(row["id"])
                    for row in conn.execute(
                        f"SELECT id FROM messages WHERE {where}",  # noqa: S608
                        params,
                    )
                )
        return len(seen)

    def recent_verification_material(
        self, *, account: str | None, since: str, limit: int
    ) -> list[dict[str, Any]]:
        """Return bounded raw text solely for the verification-code policy module.

        General MCP read methods deliberately redact authentication codes. This
        narrow method keeps extraction possible while enforcing recency, body
        truncation, account filtering, and a hard result bound at the archive
        boundary.
        """
        bounded = max(1, min(int(limit), 100))
        clauses = ["date_received>=?"]
        params: list[Any] = [_utc_boundary(since)]
        if account:
            clauses.append("account=?")
            params.append(account)
        where = " AND ".join(clauses)
        sql = f"SELECT id,account,sender_email,subject,date_received,body_text FROM messages WHERE {where} ORDER BY date_received DESC LIMIT ?"  # noqa: S608 - fixed clauses
        rows = self._collect(sql, params, bounded)
        return [
            {
                "id": str(row["id"]),
                "account": str(row["account"]),
                "sender_email": str(row["sender_email"] or "")[:500],
                "subject": str(row["subject"] or "")[:2000],
                "date_received": str(row["date_received"] or ""),
                "body_text": str(row["body_text"] or "")[: self.max_body_chars],
            }
            for row in rows
        ]

    def search(
        self,
        query: str,
        *,
        account: str | None = None,
        folder: str | None = None,
        since: str | None = None,
        before: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if not query.strip() or len(query) > 500:
            raise ValueError("query must contain 1-500 characters")
        clauses, params = ["messages_fts MATCH ?"], [query.strip()]
        if account:
            clauses.append("m.account=?")
            params.append(account)
        if folder:
            clauses.append("m.folder=?")
            params.append(folder)
        if since:
            clauses.append("m.date_received>=?")
            params.append(_utc_boundary(since))
        if before:
            clauses.append("m.date_received<?")
            params.append(_utc_boundary(before))
        bounded = self._limit(limit)
        # `clauses` contains fixed SQL fragments; search input stays parameterized.
        sql = (
            "SELECT m.*,snippet(messages_fts,2,'[',']',' … ',18) AS body_snippet "  # noqa: S608
            "FROM messages_fts JOIN messages m ON m.rowid=messages_fts.rowid "
            f"WHERE {' AND '.join(clauses)} ORDER BY date_received DESC LIMIT ?"
        )
        try:
            rows = self._collect(
                sql,
                params,
                bounded,
                # A seeded shard without the FTS index must degrade to the
                # remaining databases, not fail every search as a syntax error.
                required_table="messages_fts",
            )
        except sqlite3.OperationalError as exc:
            # Plain text such as "WH-1000XM5", "a@example.com" or "can't" is not valid
            # FTS5 syntax; retry once with every word as a literal phrase.
            literal = _literal_fts_query(query)
            if literal == params[0]:
                raise ValueError("search query syntax is invalid") from exc
            params[0] = literal
            try:
                rows = self._collect(
                    sql,
                    params,
                    bounded,
                    required_table="messages_fts",
                )
            except sqlite3.OperationalError as retry_exc:
                raise ValueError("search query syntax is invalid") from retry_exc
        return [
            {
                **self._public(row),
                "body_snippet": redact_text(str(row["body_snippet"] or ""))[:3000],
            }
            for row in rows
        ]

    def get_message(self, stable_id: str, *, include_body: bool = True) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{24}", stable_id):
            raise ValueError("message id must be 24 lowercase hex characters")
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                row = conn.execute("SELECT * FROM messages WHERE id=?", (stable_id,)).fetchone()
                if row:
                    result = self._public(row)
                    if include_body:
                        result["body_text"] = redact_text(str(row["body_text"] or ""))[
                            : self.max_body_chars
                        ]
                        result["body_html"] = None
                        result["body_truncated"] = len(str(row["body_text"] or "")) > (
                            self.max_body_chars
                        )
                        result["body_fetched"] = bool(row["body_fetched"])
                        result["raw_body_sha256"] = row["raw_body_sha256"]
                    return result
        raise ValueError("message not found")

    def list_folders(self, account: str | None = None) -> list[dict[str, Any]]:
        rows: dict[tuple[str, str], dict[str, Any]] = {}
        seen: set[str] = set()
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                for row in conn.execute(
                    "SELECT id,account,folder,date_received FROM messages "
                    "WHERE (? IS NULL OR account=?)",
                    (account, account),
                ):
                    stable_id = str(row["id"])
                    if stable_id in seen:
                        continue
                    seen.add(stable_id)
                    key = (str(row["account"]), str(row["folder"] or ""))
                    item = rows.setdefault(
                        key,
                        {
                            "account": key[0],
                            "folder": key[1],
                            "messages": 0,
                            "latest": None,
                        },
                    )
                    item["messages"] += 1
                    if row["date_received"] and (
                        item["latest"] is None or row["date_received"] > item["latest"]
                    ):
                        item["latest"] = row["date_received"]
        return sorted(rows.values(), key=lambda item: (item["account"], item["folder"]))

    def sync_status(self) -> list[dict[str, Any]]:
        hot = self.data_dir / "mail-hot.db"
        if not hot.is_file():
            return []
        observed: dict[tuple[str, str], dict[str, Any]] = {}
        with closing(open_readonly(hot)) as conn:
            tables = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if "shadow_sync_state" in tables:
                for row in conn.execute(
                    "SELECT account,folder,uid_validity,last_uid,last_synced_at "
                    "FROM shadow_sync_state ORDER BY account,folder"
                ):
                    observed[(row["account"], row["folder"])] = dict(row)
            if "sync_attempts" in tables:
                for row in conn.execute(
                    "SELECT account,folder,status,reason_code,attempted_at FROM sync_attempts"
                ):
                    item = observed.setdefault(
                        (row["account"], row["folder"]),
                        {
                            "account": row["account"],
                            "folder": row["folder"],
                            "uid_validity": None,
                            "last_uid": None,
                            "last_synced_at": None,
                        },
                    )
                    item.update(
                        last_attempt_status=row["status"],
                        last_attempt_reason=row["reason_code"],
                        last_attempt_at=row["attempted_at"],
                    )
        return [observed[key] for key in sorted(observed)]

    @staticmethod
    def _reference_ids(value: str | None) -> set[str]:
        raw = str(value or "")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        values = parsed if isinstance(parsed, list) else re.findall(r"<([^>]+)>", raw)
        if not isinstance(parsed, list) and not values and raw:
            values = raw.split()
        return {normalized for item in values if (normalized := normalize_message_id(str(item)))}

    def get_thread(self, stable_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        anchor = self._message_row(stable_id)
        thread_ids = self._reference_ids(anchor["references_ids"])
        thread_ids.add(normalize_message_id(str(anchor["message_id"] or "")))
        thread_ids.add(normalize_message_id(str(anchor["in_reply_to"] or "")))
        thread_ids.discard("")
        rows: dict[str, sqlite3.Row] = {}
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                for row in conn.execute("SELECT * FROM messages"):
                    rows.setdefault(str(row["id"]), row)
        changed = True
        selected = {stable_id}
        while changed:
            changed = False
            for row_id, row in rows.items():
                references = self._reference_ids(row["references_ids"])
                references.add(normalize_message_id(str(row["message_id"] or "")))
                references.add(normalize_message_id(str(row["in_reply_to"] or "")))
                references.discard("")
                if row_id in selected or (thread_ids and references & thread_ids):
                    if row_id not in selected or not references <= thread_ids:
                        selected.add(row_id)
                        thread_ids.update(references)
                        changed = True
        bounded = self._limit(limit)
        ordered = sorted(
            (rows[row_id] for row_id in selected if row_id in rows),
            key=lambda row: row["date_received"] or "",
        )[:bounded]
        result = []
        for row in ordered:
            item = self._public(row)
            item["body_text"] = redact_text(str(row["body_text"] or ""))[: self.max_body_chars]
            item["body_html"] = None
            result.append(item)
        return result

    def list_attachments(self, stable_id: str) -> list[dict[str, Any]]:
        self._validate_stable_id(stable_id)
        attachments: dict[str, dict[str, Any]] = {}
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                has_blobs = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='attachment_blobs'"
                ).fetchone()
                blob_ids = (
                    {
                        str(row[0])
                        for row in conn.execute(
                            "SELECT attachment_id FROM attachment_blobs WHERE message_id=?",
                            (stable_id,),
                        )
                    }
                    if has_blobs
                    else set()
                )
                for row in conn.execute(
                    "SELECT id,filename,mimetype,size FROM attachments "
                    "WHERE message_id=? ORDER BY filename,id",
                    (stable_id,),
                ):
                    attachment_id = str(row["id"])
                    existing = attachments.setdefault(
                        attachment_id,
                        {
                            "attachment_id": attachment_id,
                            "filename": safe_filename(str(row["filename"] or "")),
                            "mimetype": str(row["mimetype"] or "application/octet-stream"),
                            "size": int(row["size"] or 0),
                            "available": False,
                        },
                    )
                    existing["available"] = existing["available"] or attachment_id in blob_ids
        if not attachments and not self._message_exists(stable_id):
            raise ValueError("message not found")
        return sorted(
            attachments.values(), key=lambda item: (item["filename"], item["attachment_id"])
        )

    def download_attachment(
        self,
        stable_id: str,
        attachment_id: str,
        *,
        max_bytes: int = MAX_DOWNLOAD_BYTES,
    ) -> dict[str, Any]:
        self._validate_stable_id(stable_id)
        if not re.fullmatch(r"[0-9a-f]{20}", attachment_id):
            raise ValueError("attachment id must be 20 lowercase hex characters")
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                has_blobs = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='attachment_blobs'"
                ).fetchone()
                if not has_blobs:
                    continue
                row = conn.execute(
                    """
                    SELECT a.filename,a.mimetype,a.size,b.nonce,b.ciphertext,
                           b.content_sha256,b.content_size
                    FROM attachments a JOIN attachment_blobs b ON b.attachment_id=a.id
                    WHERE a.message_id=? AND a.id=? AND b.message_id=a.message_id
                    """,
                    (stable_id, attachment_id),
                ).fetchone()
                if not row:
                    continue
                if self._attachment_cipher is None:
                    raise RuntimeError("attachment decryption key is not configured")
                try:
                    content = self._attachment_cipher.decrypt(
                        bytes(row["nonce"]),
                        bytes(row["ciphertext"]),
                        _attachment_aad(
                            attachment_id,
                            stable_id,
                            str(row["mimetype"] or ""),
                            int(row["size"]),
                        ),
                    )
                except InvalidTag as exc:
                    raise RuntimeError("attachment content authentication failed") from exc
                content_hash = hashlib.sha256(content).hexdigest()
                if (
                    content_hash != row["content_sha256"]
                    or len(content) != int(row["size"])
                    or len(content) != int(row["content_size"])
                ):
                    raise RuntimeError("attachment content integrity check failed")
                filename, mimetype = validate_download(
                    filename=str(row["filename"] or ""),
                    mimetype=str(row["mimetype"] or ""),
                    content=content,
                    requested_max_bytes=max_bytes,
                )
                return {
                    "attachment_id": attachment_id,
                    "filename": filename,
                    "mimetype": mimetype,
                    "size": len(content),
                    "sha256": content_hash,
                    "encoding": "base64",
                    "content_base64": base64.b64encode(content).decode("ascii"),
                }
        if not any(
            item["attachment_id"] == attachment_id for item in self.list_attachments(stable_id)
        ):
            raise ValueError("attachment not found")
        raise ValueError("attachment content is unavailable in this archive")

    def message_context(self, stable_id: str) -> dict[str, Any]:
        row = self._message_row(stable_id)
        keys = set(row.keys())
        return {
            **self._public(row),
            "message_id": str(row["message_id"] or ""),
            "reply_to": str(row["reply_to"] or "") if "reply_to" in keys else "",
            "in_reply_to": str(row["in_reply_to"] or ""),
            "references_ids": sorted(self._reference_ids(row["references_ids"])),
            "body_text": redact_text(str(row["body_text"] or ""))[: self.max_body_chars],
            "uid": int(row["uid"] or 0),
            "raw_body_sha256": str(row["raw_body_sha256"] or ""),
            "locations": self.message_locations(stable_id),
        }

    def message_locations(self, stable_id: str) -> list[dict[str, Any]]:
        """Return current provider locators, with hot-db tombstones overriding old shards."""
        self._validate_stable_id(stable_id)
        by_key: dict[tuple[str, str], sqlite3.Row] = {}
        found_location_history = False
        live_accounts: set[str] = set()
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='message_locations'"
                ).fetchone()
                if not exists:
                    continue
                rows = conn.execute(
                    """
                    SELECT stable_id,account,folder,uid,uid_validity,flags,
                           raw_body_sha256,active,observed_at
                    FROM message_locations WHERE stable_id=?
                    ORDER BY account,folder
                    """,
                    (stable_id,),
                ).fetchall()
                if path == self.data_dir / "mail-hot.db":
                    has_live_sync = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='shadow_sync_state'"
                    ).fetchone()
                    if has_live_sync:
                        live_accounts = {
                            str(row[0])
                            for row in conn.execute(
                                "SELECT DISTINCT account FROM shadow_sync_state WHERE uid_validity<>''"
                            )
                        }
                found_location_history = found_location_history or bool(rows)
                for row in rows:
                    # For synchronized accounts the hot locator index is
                    # authoritative, including an absent identity. Year shards
                    # retain historical UIDs that must not be used for actions.
                    if (
                        path != self.data_dir / "mail-hot.db"
                        and str(row["account"]) in live_accounts
                    ):
                        continue
                    by_key.setdefault((str(row["account"]), str(row["folder"])), row)
                # The hot database is the central live locator index populated
                # by the full provider backfill and subsequent folder snapshots.
                # If it knows this identity, older shard-local copies must not
                # resurrect a location that is absent or tombstoned there.
                if path == self.data_dir / "mail-hot.db" and rows:
                    break
        if not found_location_history:
            row = self._message_row(stable_id)
            if str(row["account"]) in live_accounts:
                return []
            if row["folder"] and int(row["uid"] or 0) > 0:
                return [
                    {
                        "account": str(row["account"]),
                        "folder": str(row["folder"]),
                        "uid": int(row["uid"]),
                        "uid_validity": "",
                        "flags": self._flags(row["flags"]),
                        "raw_body_sha256": str(row["raw_body_sha256"] or ""),
                        "observed_at": str(row["updated_at"] or row["fetched_at"] or ""),
                    }
                ]
            return []
        return [
            {
                "account": str(row["account"]),
                "folder": str(row["folder"]),
                "uid": int(row["uid"]),
                "uid_validity": str(row["uid_validity"] or ""),
                "flags": self._flags(row["flags"]),
                "raw_body_sha256": str(row["raw_body_sha256"] or ""),
                "observed_at": str(row["observed_at"] or ""),
            }
            for row in by_key.values()
            if bool(row["active"]) and int(row["uid"] or 0) > 0
        ]

    @staticmethod
    def _validate_stable_id(stable_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{24}", stable_id):
            raise ValueError("message id must be 24 lowercase hex characters")

    def _message_row(self, stable_id: str) -> sqlite3.Row:
        self._validate_stable_id(stable_id)
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                row = conn.execute("SELECT * FROM messages WHERE id=?", (stable_id,)).fetchone()
                if row:
                    return row
        raise ValueError("message not found")

    def _message_exists(self, stable_id: str) -> bool:
        try:
            self._message_row(stable_id)
        except ValueError:
            return False
        return True

    def stats(self) -> dict[str, Any]:
        accounts: dict[str, dict[str, Any]] = {}
        seen: set[str] = set()
        for path in self.paths():
            with closing(open_readonly(path)) as conn:
                for row in conn.execute("SELECT id,account,date_received FROM messages"):
                    if row["id"] in seen:
                        continue
                    seen.add(row["id"])
                    item = accounts.setdefault(row["account"], {"messages": 0, "latest": None})
                    item["messages"] += 1
                    # A malformed source date sorts above every genuine message,
                    # so an implausible year must never become "latest".
                    if _is_plausible_date(row["date_received"]) and (
                        not item["latest"] or row["date_received"] > item["latest"]
                    ):
                        item["latest"] = row["date_received"]
        return {
            "accounts": accounts,
            "messages": len(seen),
            "shards": [path.name for path in self.paths()],
            "generated_at": _utc_now(),
            "mode": "read-only archive",
            "freshness_note": (
                "Archive dates are source-message values and may contain malformed metadata."
            ),
        }

    @staticmethod
    def _public(row: sqlite3.Row) -> dict[str, Any]:
        flags = ArchiveReader._flags(row["flags"])
        return {
            "id": row["id"],
            "account": row["account"],
            "folder": row["folder"],
            "sender_name": redact_text(str(row["sender_name"] or ""))[:500],
            "sender_email": redact_text(str(row["sender_email"] or ""))[:500],
            "recipients_to": redact_text(str(row["recipients_to"] or ""))[:2000],
            "recipients_cc": redact_text(str(row["recipients_cc"] or ""))[:2000],
            "subject": redact_text(str(row["subject"] or ""))[:2000],
            "date_received": row["date_received"],
            "has_attachments": bool(row["has_attachments"]),
            "flags": flags if isinstance(flags, list) else [],
        }

    @staticmethod
    def _flags(value: object) -> list[str]:
        try:
            flags = json.loads(str(value or "[]"))
        except json.JSONDecodeError:
            return []
        return [str(item) for item in flags] if isinstance(flags, list) else []
