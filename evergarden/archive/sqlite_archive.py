from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from evergarden.archive.reader import ArchiveReader
from evergarden.archive.sqlite_base import (  # noqa: F401
    LOGGER,
    PUBLIC_MESSAGE_COLUMNS_SQL,
    SCHEMA,
    ProviderIdentityConflict,
    StaleMailboxSnapshot,
    _attachment_aad,
    _attachment_cipher,
    _dates_are_provider_equivalent,
    _harden_sqlite_files,
    _is_plausible_date,
    _mailboxes_are_provider_equivalent,
    _normalized_reference_ids,
    _private_sqlite_path,
    _reconcile_logical_locations,
    _utc_boundary,
    _utc_now,
    open_readonly,
    open_writer,
)
from evergarden.mail.models import MessageRecord, normalize_message_id


class ArchiveWriter:
    def __init__(
        self,
        data_dir: Path,
        *,
        attachment_key: bytes | None = None,
        folder_precedence: Mapping[str, Sequence[str]] | None = None,
    ):
        self.data_dir = data_dir
        self.hot_path = data_dir / "mail-hot.db"
        self._attachment_cipher = _attachment_cipher(attachment_key)
        # Alias -> logical-folder precedence, from the configured accounts.
        self.folder_precedence = dict(folder_precedence or {})

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = open_writer(self.hot_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def state_version(self, account: str) -> int:
        with closing(open_writer(self.hot_path)) as conn:
            return self._state_version(conn, account)

    @staticmethod
    def _state_version(conn: sqlite3.Connection, account: str) -> int:
        row = conn.execute(
            "SELECT version FROM mailbox_state_versions WHERE account=?", (account,)
        ).fetchone()
        return int(row[0]) if row else 0

    def apply_folder_snapshot(
        self,
        account: str,
        folder: str,
        uid_validity: str,
        current_uids: set[int],
        current_flags: dict[int, tuple[str, ...]],
        records: Iterable[MessageRecord],
        *,
        expected_version: int,
        last_uid: int | None = None,
    ) -> dict[str, Any]:
        """Commit complete provider evidence and its watermark atomically.

        A provider copy whose content conflicts with its archived identity is
        quarantined instead of failing the folder: it gets no locator, the
        archived content is untouched, and the rest of the snapshot commits.
        """
        if set(current_flags) != current_uids:
            raise ValueError("folder snapshot is missing provider flags")
        with self._transaction() as conn:
            if self._state_version(conn, account) != expected_version:
                raise StaleMailboxSnapshot("mailbox state changed while reading provider snapshot")
            now = _utc_now()
            for record in records:
                if (
                    record.account != account
                    or record.folder != folder
                    or record.uid not in current_uids
                ):
                    raise ValueError("folder snapshot contains an unrelated provider locator")
                existing = conn.execute(
                    "SELECT 1 FROM messages WHERE id=? AND account=?",
                    (record.stable_id, account),
                ).fetchone()
                if existing or self.has_message(record.stable_id, account):
                    conn.execute("SAVEPOINT provider_record")
                    try:
                        self._observe_location(
                            conn,
                            record,
                            uid_validity=uid_validity,
                            prefer_config_order=True,
                        )
                    except ProviderIdentityConflict as exc:
                        conn.execute("ROLLBACK TO provider_record")
                        conn.execute("RELEASE provider_record")
                        self._quarantine_identity_conflict(conn, exc, uid_validity, now)
                        continue
                    conn.execute("RELEASE provider_record")
                else:
                    self._upsert(conn, record, uid_validity=uid_validity, prefer_config_order=True)
                conn.execute(
                    "UPDATE provider_identity_conflicts SET cleared_at=? "
                    "WHERE account=? AND folder=? AND uid_validity=? AND uid=? "
                    "AND cleared_at IS NULL",
                    (now, account, folder, uid_validity, record.uid),
                )
            result = self._reconcile_folder_snapshot(
                conn, account, folder, uid_validity, current_uids, current_flags
            )
            result["identity_conflicts"] = self._settle_identity_conflicts(
                conn, account, folder, uid_validity, current_uids, now
            )
            if last_uid is not None:
                self._set_sync_state(conn, account, folder, uid_validity, last_uid)
            return result

    @staticmethod
    def _quarantine_identity_conflict(
        conn: sqlite3.Connection,
        conflict: ProviderIdentityConflict,
        uid_validity: str,
        now: str,
    ) -> None:
        record = conflict.record
        conn.execute(
            """
            INSERT INTO provider_identity_conflicts(
              account,folder,uid_validity,uid,stable_id,provider_raw_body_sha256,
              archive_raw_body_sha256,first_seen_at,last_seen_at,cleared_at
            ) VALUES (?,?,?,?,?,?,?,?,?,NULL)
            ON CONFLICT(account,folder,uid_validity,uid) DO UPDATE SET
              stable_id=excluded.stable_id,
              provider_raw_body_sha256=excluded.provider_raw_body_sha256,
              archive_raw_body_sha256=excluded.archive_raw_body_sha256,
              last_seen_at=excluded.last_seen_at,
              cleared_at=NULL
            """,
            (
                record.account,
                record.folder,
                uid_validity,
                record.uid,
                record.stable_id,
                record.raw_body_sha256,
                conflict.archive_raw_body_sha256,
                now,
                now,
            ),
        )
        LOGGER.warning(
            "quarantined provider identity conflict account=%s folder=%s uid=%s stable_id=%s",
            record.account,
            record.folder,
            record.uid,
            record.stable_id,
        )

    @staticmethod
    def _settle_identity_conflicts(
        conn: sqlite3.Connection,
        account: str,
        folder: str,
        uid_validity: str,
        current_uids: set[int],
        now: str,
    ) -> list[dict[str, Any]]:
        """Clear quarantined copies the provider no longer holds; return the rest."""
        open_rows = conn.execute(
            "SELECT uid_validity,uid,stable_id FROM provider_identity_conflicts "
            "WHERE account=? AND folder=? AND cleared_at IS NULL ORDER BY uid",
            (account, folder),
        ).fetchall()
        remaining = []
        for row in open_rows:
            if str(row["uid_validity"]) == uid_validity and int(row["uid"]) in current_uids:
                remaining.append({"uid": int(row["uid"]), "stable_id": str(row["stable_id"])})
                continue
            conn.execute(
                "UPDATE provider_identity_conflicts SET cleared_at=? "
                "WHERE account=? AND folder=? AND uid_validity=? AND uid=?",
                (now, account, folder, str(row["uid_validity"]), int(row["uid"])),
            )
        return remaining

    def upsert(
        self,
        record: MessageRecord,
        *,
        uid_validity: str = "",
        prefer_config_order: bool = False,
    ) -> None:
        with self._transaction() as conn:
            self._upsert(
                conn,
                record,
                uid_validity=uid_validity,
                prefer_config_order=prefer_config_order,
            )

    def _upsert(
        self,
        conn: sqlite3.Connection,
        record: MessageRecord,
        *,
        uid_validity: str = "",
        prefer_config_order: bool = False,
    ) -> None:
        now = _utc_now()
        conn.execute(
            """
            INSERT INTO messages(
              id,account,folder,uid,message_id,reply_to,sender_raw,sender_name,sender_email,
              recipients_to,recipients_cc,recipients_bcc,list_id,subject,in_reply_to,references_ids,
              date_received,body_text,body_html,
              has_attachments,flags,raw_size,body_fetched,raw_body_sha256,fetched_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              message_id=excluded.message_id,
              reply_to=excluded.reply_to,
              sender_raw=excluded.sender_raw, sender_name=excluded.sender_name,
              sender_email=excluded.sender_email, recipients_to=excluded.recipients_to,
              recipients_cc=excluded.recipients_cc, recipients_bcc=excluded.recipients_bcc,
              list_id=excluded.list_id, subject=excluded.subject,
              in_reply_to=excluded.in_reply_to, references_ids=excluded.references_ids,
              date_received=excluded.date_received, body_text=excluded.body_text,
              body_html=excluded.body_html, has_attachments=excluded.has_attachments,
              raw_size=excluded.raw_size, body_fetched=1,
              raw_body_sha256=excluded.raw_body_sha256,
              fetched_at=excluded.fetched_at, updated_at=excluded.updated_at
            """,
            (
                record.stable_id,
                record.account,
                record.folder,
                record.uid,
                record.message_id,
                record.reply_to,
                record.sender_raw,
                record.sender_name,
                record.sender_email,
                record.recipients_to,
                record.recipients_cc,
                record.recipients_bcc,
                record.list_id,
                record.subject,
                record.in_reply_to,
                json.dumps(record.references_ids),
                record.date_received,
                record.body_text,
                record.body_html,
                int(record.has_attachments),
                json.dumps(record.flags),
                record.raw_size,
                1,
                record.raw_body_sha256,
                now,
                now,
            ),
        )
        self._write_location(conn, record, uid_validity=uid_validity, observed_at=now)
        _reconcile_logical_locations(
            conn,
            stable_id=record.stable_id,
            account=record.account,
            folder_precedence=self.folder_precedence,
            prefer_config_order=prefer_config_order,
        )
        self._write_attachments(conn, record, stored_at=now)

    def import_unlocated_records(self, records: list[MessageRecord]) -> int:
        """Import received copies without claiming Thunderbird IDs are IMAP UIDs."""
        if not records:
            raise ValueError("historical archive import requires at least one record")
        identities = [(record.stable_id, record.account) for record in records]
        if len(set(identities)) != len(identities):
            raise ValueError("historical archive import contains duplicate identities")
        for stable_id, account in identities:
            if not re.fullmatch(r"[0-9a-f]{24}", stable_id) or not account:
                raise ValueError("historical archive identity is malformed")

        # Copy-only year shards may contain a row that is absent from hot.  Do
        # this read-only preflight before beginning the single hot transaction.
        for path in self._message_paths():
            if not path.is_file():
                continue
            with closing(open_readonly(path)) as existing:
                for stable_id, account in identities:
                    if existing.execute(
                        "SELECT 1 FROM messages WHERE id=? AND account=?",
                        (stable_id, account),
                    ).fetchone():
                        raise RuntimeError("historical archive identity already exists")

        conn = open_writer(self.hot_path)
        now = _utc_now()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for record in records:
                conn.execute(
                    """
                    INSERT INTO messages(
                      id,account,folder,uid,message_id,reply_to,sender_raw,sender_name,sender_email,
                      recipients_to,recipients_cc,recipients_bcc,list_id,subject,in_reply_to,
                      references_ids,date_received,body_text,body_html,has_attachments,flags,
                      raw_size,body_fetched,raw_body_sha256,fetched_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record.stable_id,
                        record.account,
                        record.folder,
                        record.uid,
                        record.message_id,
                        record.reply_to,
                        record.sender_raw,
                        record.sender_name,
                        record.sender_email,
                        record.recipients_to,
                        record.recipients_cc,
                        record.recipients_bcc,
                        record.list_id,
                        record.subject,
                        record.in_reply_to,
                        json.dumps(record.references_ids),
                        record.date_received,
                        record.body_text,
                        record.body_html,
                        int(record.has_attachments),
                        json.dumps(record.flags),
                        record.raw_size,
                        1,
                        record.raw_body_sha256,
                        now,
                        now,
                    ),
                )
                self._write_attachments(conn, record, stored_at=now)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return len(records)

    def _write_attachments(
        self,
        conn: sqlite3.Connection,
        record: MessageRecord,
        *,
        stored_at: str,
    ) -> None:
        for attachment_index, attachment in enumerate(record.attachments):
            attachment_identity = f"{record.stable_id}\0{attachment.filename}\0{attachment.size}"
            if attachment.content is not None:
                attachment_identity += (
                    f"\0{attachment_index}\0{hashlib.sha256(attachment.content).hexdigest()}"
                )
            attachment_id = hashlib.blake2b(
                attachment_identity.encode(),
                digest_size=10,
            ).hexdigest()
            # First write wins: the blob AAD binds the mimetype at encryption
            # time, so rewriting the row's mimetype on a later upsert (bridge
            # ingest vs native sync of the same message) would permanently
            # fail authentication of a valid blob. filename and size are part
            # of the id derivation and cannot differ on conflict.
            conn.execute(
                """
                INSERT INTO attachments(id,message_id,filename,mimetype,size)
                VALUES (?,?,?,?,?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    attachment_id,
                    record.stable_id,
                    attachment.filename,
                    attachment.mimetype,
                    attachment.size,
                ),
            )
            if attachment.content is not None and self._attachment_cipher is not None:
                content_hash = hashlib.sha256(attachment.content).hexdigest()
                nonce = os.urandom(12)
                ciphertext = self._attachment_cipher.encrypt(
                    nonce,
                    attachment.content,
                    _attachment_aad(
                        attachment_id,
                        record.stable_id,
                        attachment.mimetype,
                        attachment.size,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO attachment_blobs(
                      attachment_id,message_id,nonce,ciphertext,content_sha256,content_size,stored_at
                    ) VALUES (?,?,?,?,?,?,?) ON CONFLICT(attachment_id) DO NOTHING
                    """,
                    (
                        attachment_id,
                        record.stable_id,
                        nonce,
                        ciphertext,
                        content_hash,
                        attachment.size,
                        stored_at,
                    ),
                )
                existing_blob = conn.execute(
                    "SELECT message_id,content_sha256,content_size FROM attachment_blobs "
                    "WHERE attachment_id=?",
                    (attachment_id,),
                ).fetchone()
                if (
                    not existing_blob
                    or existing_blob["message_id"] != record.stable_id
                    or existing_blob["content_sha256"] != content_hash
                    or int(existing_blob["content_size"]) != attachment.size
                ):
                    raise RuntimeError("immutable attachment content conflict")

    @staticmethod
    def _write_location(
        conn: sqlite3.Connection,
        record: MessageRecord,
        *,
        uid_validity: str,
        observed_at: str,
        archive_raw_body_sha256: str | None = None,
    ) -> None:
        uid_owner = conn.execute(
            "SELECT stable_id FROM provider_uid_observations "
            "WHERE account=? AND folder=? AND uid_validity=? AND uid=?",
            (record.account, record.folder, uid_validity, record.uid),
        ).fetchone()
        if uid_owner and str(uid_owner["stable_id"]) != record.stable_id:
            raise RuntimeError("provider UID identity conflicts with locator history")
        conn.execute(
            """
            INSERT INTO provider_identity_verifications(
              account,folder,uid_validity,uid,stable_id,provider_raw_body_sha256,
              archive_raw_body_sha256,verified_at
            ) VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(account,folder,uid_validity,uid) DO UPDATE SET
              stable_id=excluded.stable_id,
              provider_raw_body_sha256=excluded.provider_raw_body_sha256,
              archive_raw_body_sha256=excluded.archive_raw_body_sha256,
              verified_at=excluded.verified_at
            """,
            (
                record.account,
                record.folder,
                uid_validity,
                record.uid,
                record.stable_id,
                record.raw_body_sha256,
                archive_raw_body_sha256 or record.raw_body_sha256,
                observed_at,
            ),
        )
        conn.execute(
            """
            INSERT INTO provider_uid_observations(
              account,folder,uid_validity,uid,stable_id,flags,
              raw_body_sha256,active,observed_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(account,folder,uid_validity,uid) DO UPDATE SET
              stable_id=excluded.stable_id,
              flags=excluded.flags,
              raw_body_sha256=excluded.raw_body_sha256,
              active=1,
              observed_at=excluded.observed_at
            """,
            (
                record.account,
                record.folder,
                uid_validity,
                record.uid,
                record.stable_id,
                json.dumps(record.flags),
                record.raw_body_sha256,
                1,
                observed_at,
            ),
        )
        conn.execute(
            """
            INSERT INTO message_locations(
              stable_id,account,folder,uid,uid_validity,flags,raw_body_sha256,
              active,observed_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(stable_id,account,folder) DO UPDATE SET
              uid=CASE WHEN message_locations.active=0 THEN excluded.uid
                       ELSE message_locations.uid END,
              uid_validity=CASE WHEN message_locations.active=0 OR (
                                  message_locations.uid=excluded.uid AND (
                                    message_locations.uid_validity=excluded.uid_validity OR
                                    message_locations.uid_validity='' OR excluded.uid_validity=''
                                  )
                                ) THEN excluded.uid_validity
                                ELSE message_locations.uid_validity END,
              flags=CASE WHEN message_locations.active=0 OR (
                           message_locations.uid=excluded.uid AND (
                             message_locations.uid_validity=excluded.uid_validity OR
                             message_locations.uid_validity='' OR excluded.uid_validity=''
                           )
                         ) THEN excluded.flags
                         ELSE message_locations.flags END,
              raw_body_sha256=CASE WHEN message_locations.active=0 OR (
                                     message_locations.uid=excluded.uid AND (
                                       message_locations.uid_validity=excluded.uid_validity OR
                                       message_locations.uid_validity='' OR excluded.uid_validity=''
                                     )
                                   )
                                   THEN excluded.raw_body_sha256
                                   ELSE message_locations.raw_body_sha256 END,
              active=1,
              observed_at=excluded.observed_at
            """,
            (
                record.stable_id,
                record.account,
                record.folder,
                record.uid,
                uid_validity,
                json.dumps(record.flags),
                record.raw_body_sha256,
                1,
                observed_at,
            ),
        )

    def observe_location(
        self,
        record: MessageRecord,
        *,
        uid_validity: str,
        prefer_config_order: bool = False,
    ) -> None:
        """Verify a provider locator while preserving archived content and identity."""
        with self._transaction() as conn:
            self._observe_location(
                conn,
                record,
                uid_validity=uid_validity,
                prefer_config_order=prefer_config_order,
            )

    def _observe_location(
        self,
        conn: sqlite3.Connection,
        record: MessageRecord,
        *,
        uid_validity: str,
        prefer_config_order: bool = False,
    ) -> None:
        """Verify a provider locator while preserving archived content and identity."""
        existing = conn.execute(
            "SELECT * FROM messages WHERE id=? AND account=?",
            (record.stable_id, record.account),
        ).fetchone()
        if existing is None:
            existing = self._restore_archived_message(conn, record)
        existing_hash = str(existing["raw_body_sha256"] or "") if existing else ""
        if (
            existing is not None
            and existing_hash != record.raw_body_sha256
            and not self._provider_variant_matches(conn, existing, record)
        ):
            raise ProviderIdentityConflict(record, existing_hash)
        self._write_location(
            conn,
            record,
            uid_validity=uid_validity,
            observed_at=_utc_now(),
            archive_raw_body_sha256=existing_hash,
        )
        _reconcile_logical_locations(
            conn,
            stable_id=record.stable_id,
            account=record.account,
            folder_precedence=self.folder_precedence,
            prefer_config_order=prefer_config_order,
        )

    def _restore_archived_message(
        self, hot: sqlite3.Connection, record: MessageRecord
    ) -> sqlite3.Row | None:
        """Restore a verified shard row, never copying its stale provider locations."""
        for path in ArchiveReader(self.data_dir).paths():
            if path == self.hot_path:
                continue
            with closing(open_readonly(path)) as source:
                source.execute("BEGIN")
                archived = source.execute(
                    "SELECT * FROM messages WHERE id=? AND account=?",
                    (record.stable_id, record.account),
                ).fetchone()
                if archived is None:
                    continue
                if str(archived["raw_body_sha256"] or "") != record.raw_body_sha256 and not (
                    self._provider_variant_matches(source, archived, record)
                ):
                    raise ProviderIdentityConflict(record, str(archived["raw_body_sha256"] or ""))
                tables = {
                    str(row[0])
                    for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                for table in ("messages", "attachments", "attachment_blobs"):
                    if table != "messages":
                        hot.execute(
                            f"DELETE FROM {table} WHERE message_id=?",  # noqa: S608 - fixed table names
                            (record.stable_id,),
                        )
                    if table not in tables:
                        continue
                    columns = [str(row[1]) for row in hot.execute(f"PRAGMA table_info({table})")]
                    key = "id" if table == "messages" else "message_id"
                    rows = source.execute(
                        f"SELECT * FROM {table} WHERE {key}=?",  # noqa: S608 - fixed table and key names
                        (record.stable_id,),
                    ).fetchall()
                    for row in rows:
                        shared = [column for column in columns if column in row.keys()]
                        if table == "messages":
                            # Legacy shards predate these optional envelope fields.
                            shared.extend(
                                column
                                for column in ("reply_to", "recipients_bcc", "list_id")
                                if column in columns and column not in shared
                            )
                        marks = ",".join("?" for _ in shared)
                        hot.execute(
                            f"INSERT INTO {table}({','.join(shared)}) VALUES ({marks})",  # noqa: S608 - schema identifiers
                            tuple(
                                row[column] if column in row.keys() else getattr(record, column)
                                for column in shared
                            ),
                        )
                return hot.execute(
                    "SELECT * FROM messages WHERE id=? AND account=?",
                    (record.stable_id, record.account),
                ).fetchone()
        return None

    @staticmethod
    def _provider_variant_matches(
        conn: sqlite3.Connection,
        existing: sqlite3.Row,
        record: MessageRecord,
    ) -> bool:
        """Recognize a provider-reencoded copy without trusting Message-ID alone."""
        existing_fields = set(existing.keys())
        existing_message_id = normalize_message_id(str(existing["message_id"] or ""))
        if not existing_message_id or existing_message_id != normalize_message_id(
            record.message_id
        ):
            return False
        exact_fields = (
            "sender_raw",
            "sender_name",
            "sender_email",
            "list_id",
            "subject",
            "in_reply_to",
            "body_text",
            "body_html",
        )
        if any(
            str(existing[field] or "") != str(getattr(record, field) or "")
            for field in exact_fields
            if field in existing_fields
        ):
            return False
        if any(
            not _mailboxes_are_provider_equivalent(existing[field], getattr(record, field))
            for field in ("reply_to", "recipients_to", "recipients_cc", "recipients_bcc")
            if field in existing_fields
        ):
            return False
        if _normalized_reference_ids(existing["references_ids"]) != tuple(
            sorted(
                normalized
                for item in record.references_ids
                if (normalized := normalize_message_id(item))
            )
        ):
            return False
        if bool(existing["has_attachments"]) != bool(record.has_attachments):
            return False
        if not _dates_are_provider_equivalent(existing["date_received"], record.date_received):
            return False
        tables = {
            str(row["name"])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name IN ('attachments','attachment_blobs')"
            )
        }
        if "attachments" not in tables:
            stored_attachments = []
        elif "attachment_blobs" in tables:
            stored_attachments = conn.execute(
                "SELECT a.filename,a.mimetype,a.size,b.content_sha256 "
                "FROM attachments a LEFT JOIN attachment_blobs b ON b.attachment_id=a.id "
                "AND b.message_id=a.message_id WHERE a.message_id=?",
                (record.stable_id,),
            ).fetchall()
        else:
            stored_attachments = conn.execute(
                "SELECT filename,mimetype,size,NULL AS content_sha256 "
                "FROM attachments WHERE message_id=?",
                (record.stable_id,),
            ).fetchall()
        stored_shapes = sorted(
            (str(row["filename"] or ""), str(row["mimetype"] or ""), int(row["size"] or 0))
            for row in stored_attachments
        )
        observed_shapes = sorted(
            (item.filename, item.mimetype, item.size) for item in record.attachments
        )
        if stored_shapes != observed_shapes:
            return False
        if (
            stored_attachments
            and all(row["content_sha256"] for row in stored_attachments)
            and all(item.content is not None for item in record.attachments)
        ):
            stored_content = sorted(
                (
                    str(row["filename"] or ""),
                    str(row["mimetype"] or ""),
                    int(row["size"] or 0),
                    str(row["content_sha256"]),
                )
                for row in stored_attachments
            )
            observed_content = sorted(
                (
                    item.filename,
                    item.mimetype,
                    item.size,
                    hashlib.sha256(item.content or b"").hexdigest(),
                )
                for item in record.attachments
            )
            if stored_content != observed_content:
                return False
        return True

    def has_message(self, stable_id: str, account: str) -> bool:
        for path in self._message_paths():
            if not path.is_file():
                continue
            with closing(open_readonly(path)) as conn:
                if conn.execute(
                    "SELECT 1 FROM messages WHERE id=? AND account=?",
                    (stable_id, account),
                ).fetchone():
                    return True
        return False

    def reconcile_folder_snapshot(
        self,
        account: str,
        folder: str,
        uid_validity: str,
        current_uids: set[int],
        current_flags: dict[int, tuple[str, ...]] | None = None,
    ) -> dict[str, int]:
        """Apply a local snapshot; production sync uses versioned apply_folder_snapshot."""
        with self._transaction() as conn:
            return self._reconcile_folder_snapshot(
                conn, account, folder, uid_validity, current_uids, current_flags
            )

    def _reconcile_folder_snapshot(
        self,
        conn: sqlite3.Connection,
        account: str,
        folder: str,
        uid_validity: str,
        current_uids: set[int],
        current_flags: dict[int, tuple[str, ...]] | None = None,
    ) -> dict[str, int]:
        """Make the local locator index reflect a read-only provider folder snapshot."""
        changed_ids: set[str] = set()
        reactivated_ids: set[str] = set()
        deactivated = 0
        reactivated = 0
        flags_updated = 0
        observation_rows = conn.execute(
            "SELECT stable_id,uid,uid_validity,flags,active "
            "FROM provider_uid_observations "
            "WHERE account=? AND folder=?",
            (account, folder),
        ).fetchall()
        now = _utc_now()
        for row in observation_rows:
            should_be_active = (
                str(row["uid_validity"]) == uid_validity and int(row["uid"]) in current_uids
            )
            was_active = bool(row["active"])
            encoded_flags = str(row["flags"] or "[]")
            if should_be_active and current_flags is not None:
                encoded_flags = json.dumps(current_flags[int(row["uid"])])
            flags_changed = encoded_flags != str(row["flags"] or "[]")
            if should_be_active == was_active and not flags_changed:
                continue
            conn.execute(
                "UPDATE provider_uid_observations SET active=?,flags=?,observed_at=? "
                "WHERE account=? AND folder=? AND uid_validity=? AND uid=?",
                (
                    int(should_be_active),
                    encoded_flags,
                    now,
                    account,
                    folder,
                    str(row["uid_validity"]),
                    int(row["uid"]),
                ),
            )

        canonical_rows = {
            str(row["stable_id"]): row
            for row in conn.execute(
                "SELECT stable_id,uid,uid_validity,flags,raw_body_sha256,active "
                "FROM message_locations WHERE account=? AND folder=?",
                (account, folder),
            )
        }
        stable_ids = set(canonical_rows)
        stable_ids.update(str(row["stable_id"]) for row in observation_rows)
        for stable_id in sorted(stable_ids):
            canonical = canonical_rows.get(stable_id)
            candidates = conn.execute(
                "SELECT uid,uid_validity,flags,raw_body_sha256 FROM provider_uid_observations "
                "WHERE stable_id=? AND account=? AND folder=? AND active=1 ORDER BY uid",
                (stable_id, account, folder),
            ).fetchall()
            chosen = None
            if canonical:
                chosen = next(
                    (
                        row
                        for row in candidates
                        if int(row["uid"]) == int(canonical["uid"])
                        and str(row["uid_validity"]) == str(canonical["uid_validity"])
                    ),
                    None,
                )
            chosen = chosen or (candidates[0] if candidates else None)
            was_active = bool(canonical["active"]) if canonical else False
            if chosen is None:
                if canonical and was_active:
                    reason = (
                        "UIDVALIDITY_CHANGED"
                        if str(canonical["uid_validity"]) != uid_validity
                        else "UID_ABSENT_FROM_PROVIDER_SNAPSHOT"
                    )
                    conn.execute(
                        "INSERT INTO location_events(stable_id,account,folder,reason_code,recorded_at) "
                        "VALUES (?,?,?,?,?)",
                        (stable_id, account, folder, reason, now),
                    )
                    conn.execute(
                        "UPDATE message_locations SET active=0,observed_at=? "
                        "WHERE stable_id=? AND account=? AND folder=?",
                        (now, stable_id, account, folder),
                    )
                    changed_ids.add(stable_id)
                    deactivated += 1
                continue
            chosen_values = (
                int(chosen["uid"]),
                str(chosen["uid_validity"]),
                str(chosen["flags"] or "[]"),
                str(chosen["raw_body_sha256"] or ""),
            )
            if canonical is None:
                conn.execute(
                    "INSERT INTO message_locations(stable_id,account,folder,uid,uid_validity,"
                    "flags,raw_body_sha256,active,observed_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (stable_id, account, folder, *chosen_values, 1, now),
                )
                changed_ids.add(stable_id)
                reactivated += 1
                reactivated_ids.add(stable_id)
                continue
            current_values = (
                int(canonical["uid"]),
                str(canonical["uid_validity"]),
                str(canonical["flags"] or "[]"),
                str(canonical["raw_body_sha256"] or ""),
            )
            if was_active and current_values == chosen_values:
                continue
            conn.execute(
                "UPDATE message_locations SET uid=?,uid_validity=?,flags=?,raw_body_sha256=?,"
                "active=1,observed_at=? WHERE stable_id=? AND account=? AND folder=?",
                (*chosen_values, now, stable_id, account, folder),
            )
            changed_ids.add(stable_id)
            if not was_active:
                reactivated += 1
                reactivated_ids.add(stable_id)
            if str(canonical["flags"] or "[]") != chosen_values[2]:
                flags_updated += 1
        for message_id in changed_ids:
            _reconcile_logical_locations(
                conn,
                stable_id=message_id,
                account=account,
                folder_precedence=self.folder_precedence,
                prefer_config_order=message_id in reactivated_ids,
            )
        return {
            "deactivated": deactivated,
            "reactivated": reactivated,
            "flags_updated": flags_updated,
        }

    def sync_state(self, account: str, folder: str) -> tuple[str, int] | None:
        conn = open_writer(self.hot_path)
        row = conn.execute(
            "SELECT uid_validity,last_uid FROM shadow_sync_state WHERE account=? AND folder=?",
            (account, folder),
        ).fetchone()
        conn.close()
        return (str(row["uid_validity"]), int(row["last_uid"])) if row else None

    def known_location_uids(self, account: str, folder: str, uid_validity: str) -> set[int]:
        """Return every provider UID already identified for one mailbox epoch.

        Destination UIDs are not guaranteed to exceed a folder's existing
        watermark after a provider-side MOVE.  The complete UID snapshot is
        therefore compared with this locator set during every read-only sync.
        A quarantined identity conflict counts as identified, so it is not
        fetched again each run; clearing its quarantine row rediscovers it.
        """
        if not self.hot_path.is_file():
            return set()
        with closing(open_readonly(self.hot_path)) as conn:
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                    "('provider_uid_observations','provider_identity_conflicts')"
                )
            }
            if "provider_uid_observations" not in tables:
                return set()
            uids = {
                int(row[0])
                for row in conn.execute(
                    "SELECT uid FROM provider_uid_observations "
                    "WHERE account=? AND folder=? AND uid_validity=? AND uid>0",
                    (account, folder, uid_validity),
                )
            }
            if "provider_identity_conflicts" in tables:
                uids.update(
                    int(row[0])
                    for row in conn.execute(
                        "SELECT uid FROM provider_identity_conflicts "
                        "WHERE account=? AND folder=? AND uid_validity=? AND cleared_at IS NULL",
                        (account, folder, uid_validity),
                    )
                )
            return uids

    def set_sync_state(self, account: str, folder: str, uid_validity: str, last_uid: int) -> None:
        with self._transaction() as conn:
            self._set_sync_state(conn, account, folder, uid_validity, last_uid)

    @staticmethod
    def _set_sync_state(
        conn: sqlite3.Connection, account: str, folder: str, uid_validity: str, last_uid: int
    ) -> None:
        conn.execute(
            """
            INSERT INTO shadow_sync_state(account,folder,uid_validity,last_uid,last_synced_at)
            VALUES (?,?,?,?,?)
            ON CONFLICT(account,folder) DO UPDATE SET
              uid_validity=excluded.uid_validity,last_uid=excluded.last_uid,
              last_synced_at=excluded.last_synced_at
            """,
            (account, folder, uid_validity, last_uid, _utc_now()),
        )

    def record_sync_attempt(
        self,
        account: str,
        folder: str,
        sync_run_id: str,
        status: str,
        reason_code: str | None,
        *,
        started_at: str | None = None,
    ) -> None:
        now = dt.datetime.now(dt.UTC).isoformat(timespec="microseconds")
        started_at = started_at or now
        with self._transaction() as conn:
            previous = conn.execute(
                "SELECT started_at FROM sync_attempt_order WHERE account=? AND folder=?",
                (account, folder),
            ).fetchone()
            if previous and str(previous[0]) > started_at:
                return
            conn.execute(
                "INSERT INTO sync_attempt_order(account,folder,started_at) VALUES (?,?,?) "
                "ON CONFLICT(account,folder) DO UPDATE SET started_at=excluded.started_at",
                (account, folder, started_at),
            )
            conn.execute(
                "INSERT INTO sync_attempts(account,folder,sync_run_id,status,reason_code,attempted_at) "
                "VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(account,folder) DO UPDATE SET "
                "sync_run_id=excluded.sync_run_id,status=excluded.status,"
                "reason_code=excluded.reason_code,attempted_at=excluded.attempted_at",
                (account, folder, sync_run_id, status, reason_code, now),
            )

    def confirm_move(
        self,
        stable_id: str,
        *,
        account: str,
        source: str,
        destination: str,
        destination_uid: int | None,
        destination_uid_validity: str = "",
        destination_flags: tuple[str, ...] | None = None,
        source_preserved: bool = False,
    ) -> int:
        """Record a confirmed organization result without deleting local history."""
        updated = 0
        for path in self._message_paths():
            if not path.is_file():
                continue
            conn = open_writer(path)
            now = _utc_now()
            cursor = conn.execute(
                "UPDATE messages SET folder=?,uid=?,flags=COALESCE(?,flags),updated_at=? "
                "WHERE id=? AND account=?",
                (
                    destination,
                    destination_uid or 0,
                    json.dumps(destination_flags) if destination_flags is not None else None,
                    now,
                    stable_id,
                    account,
                ),
            )
            updated += max(0, int(cursor.rowcount))
            if not source_preserved:
                conn.execute(
                    "INSERT INTO location_events(stable_id,account,folder,reason_code,recorded_at) "
                    "VALUES (?,?,?,?,?)",
                    (stable_id, account, source, "PROVIDER_MOVE_CONFIRMED", now),
                )
                conn.execute(
                    """
                    UPDATE message_locations SET active=0,observed_at=?
                    WHERE stable_id=? AND account=? AND folder=?
                    """,
                    (now, stable_id, account, source),
                )
                conn.execute(
                    "UPDATE provider_uid_observations SET active=0,observed_at=? "
                    "WHERE stable_id=? AND account=? AND folder=?",
                    (now, stable_id, account, source),
                )
            if destination_uid:
                message = conn.execute(
                    "SELECT flags,raw_body_sha256 FROM messages WHERE id=? AND account=?",
                    (stable_id, account),
                ).fetchone()
                if message:
                    encoded_flags = (
                        json.dumps(destination_flags)
                        if destination_flags is not None
                        else str(message["flags"] or "[]")
                    )
                    uid_owner = conn.execute(
                        "SELECT stable_id FROM provider_uid_observations "
                        "WHERE account=? AND folder=? AND uid_validity=? AND uid=?",
                        (account, destination, destination_uid_validity, destination_uid),
                    ).fetchone()
                    if uid_owner and str(uid_owner["stable_id"]) != stable_id:
                        conn.rollback()
                        conn.close()
                        raise RuntimeError("confirmed provider UID conflicts with locator history")
                    conn.execute(
                        """
                        INSERT INTO provider_uid_observations(
                          account,folder,uid_validity,uid,stable_id,flags,
                          raw_body_sha256,active,observed_at
                        ) VALUES (?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(account,folder,uid_validity,uid) DO UPDATE SET
                          stable_id=excluded.stable_id,
                          flags=excluded.flags,
                          raw_body_sha256=excluded.raw_body_sha256,
                          active=1,
                          observed_at=excluded.observed_at
                        """,
                        (
                            account,
                            destination,
                            destination_uid_validity,
                            destination_uid,
                            stable_id,
                            encoded_flags,
                            str(message["raw_body_sha256"] or ""),
                            1,
                            now,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO message_locations(
                          stable_id,account,folder,uid,uid_validity,flags,
                          raw_body_sha256,active,observed_at
                        ) VALUES (?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(stable_id,account,folder) DO UPDATE SET
                          uid=excluded.uid,
                          uid_validity=CASE
                            WHEN excluded.uid_validity<>'' THEN excluded.uid_validity
                            ELSE message_locations.uid_validity
                          END,
                          flags=excluded.flags,
                          raw_body_sha256=excluded.raw_body_sha256,
                          active=1,
                          observed_at=excluded.observed_at
                        """,
                        (
                            stable_id,
                            account,
                            destination,
                            destination_uid,
                            destination_uid_validity,
                            encoded_flags,
                            str(message["raw_body_sha256"] or ""),
                            1,
                            now,
                        ),
                    )
            conn.commit()
            conn.close()
        if not updated:
            raise ValueError("message not found while updating provider-confirmed location")
        return updated

    def update_flags(
        self,
        stable_id: str,
        *,
        account: str,
        flags: tuple[str, ...],
    ) -> int:
        """Apply provider-confirmed reversible flags to every local copy."""
        updated = 0
        encoded = json.dumps(flags)
        for path in self._message_paths():
            if not path.is_file():
                continue
            conn = open_writer(path)
            cursor = conn.execute(
                "UPDATE messages SET flags=?,updated_at=? WHERE id=? AND account=?",
                (encoded, _utc_now(), stable_id, account),
            )
            updated += max(0, int(cursor.rowcount))
            conn.execute(
                "UPDATE message_locations SET flags=?,observed_at=? "
                "WHERE stable_id=? AND account=? AND active=1",
                (encoded, _utc_now(), stable_id, account),
            )
            conn.execute(
                "UPDATE provider_uid_observations SET flags=?,observed_at=? "
                "WHERE stable_id=? AND account=? AND active=1",
                (encoded, _utc_now(), stable_id, account),
            )
            conn.commit()
            conn.close()
        if not updated:
            raise ValueError("message not found while updating provider-confirmed flags")
        return updated

    def update_location_flags(
        self,
        stable_id: str,
        *,
        account: str,
        folder: str,
        uid: int,
        flags: tuple[str, ...],
    ) -> int:
        """Apply provider-confirmed flags only to one folder-scoped copy."""
        updated = 0
        encoded = json.dumps(flags)
        for path in self._message_paths():
            if not path.is_file():
                continue
            conn = open_writer(path)
            now = _utc_now()
            location_cursor = conn.execute(
                "UPDATE message_locations SET flags=?,observed_at=? "
                "WHERE stable_id=? AND account=? AND folder=? AND uid=? AND active=1",
                (encoded, now, stable_id, account, folder, uid),
            )
            observation_cursor = conn.execute(
                "UPDATE provider_uid_observations SET flags=?,observed_at=? "
                "WHERE stable_id=? AND account=? AND folder=? AND uid=? AND active=1",
                (encoded, now, stable_id, account, folder, uid),
            )
            message_cursor = conn.execute(
                "UPDATE messages SET flags=?,updated_at=? "
                "WHERE id=? AND account=? AND folder=? AND uid=?",
                (encoded, now, stable_id, account, folder, uid),
            )
            updated += max(0, int(location_cursor.rowcount))
            updated += max(0, int(observation_cursor.rowcount))
            updated += max(0, int(message_cursor.rowcount))
            conn.commit()
            conn.close()
        if not updated:
            raise ValueError("provider location not found while updating confirmed flags")
        return updated

    def _message_paths(self) -> list[Path]:
        return [
            self.hot_path,
            *sorted(self.data_dir.glob("mail-[0-9][0-9][0-9][0-9].db")),
            self.data_dir / "mail-unknown.db",
        ]

    def initial_last_uid(self, account: str, folder: str) -> int:
        """Read the imported legacy watermark and all seeded shards without modifying them."""
        candidates = [self.hot_path]
        candidates.extend(sorted(self.data_dir.glob("mail-[0-9][0-9][0-9][0-9].db")))
        candidates.append(self.data_dir / "mail-unknown.db")
        high = 0
        for path in candidates:
            if not path.is_file():
                continue
            with closing(open_readonly(path)) as conn:
                high = max(
                    high,
                    int(
                        conn.execute(
                            "SELECT COALESCE(MAX(uid),0) FROM messages WHERE account=? AND folder=?",
                            (account, folder),
                        ).fetchone()[0]
                        or 0
                    ),
                )
                if path == self.hot_path:
                    has_legacy = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_state'"
                    ).fetchone()
                    if has_legacy:
                        row = conn.execute(
                            "SELECT last_uid FROM sync_state WHERE account=? AND folder=?",
                            (account, folder),
                        ).fetchone()
                        if row:
                            high = max(high, int(row[0]))
        return high

    def rollover_copy_only(self, *, scheduled_slot: str, cutoff: dt.date) -> dict[str, Any]:
        """Copy settled rows to year shards without deleting the hot source."""
        hot = open_writer(self.hot_path)
        existing = hot.execute(
            "SELECT copied_count,source_hash FROM shadow_rollover_ledger WHERE scheduled_slot=?",
            (scheduled_slot,),
        ).fetchone()
        if existing:
            hot.close()
            return {
                "copied": int(existing["copied_count"]),
                "source_hash": existing["source_hash"],
                "replayed": True,
            }
        rows = hot.execute(
            "SELECT * FROM messages WHERE substr(date_received,1,10) < ? ORDER BY id",
            (cutoff.isoformat(),),
        ).fetchall()
        digest = hashlib.sha256("\n".join(str(row["id"]) for row in rows).encode()).hexdigest()
        copied = 0
        by_year: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            year = str(row["date_received"] or "")[:4]
            if not re.fullmatch(r"(?:19|20)\d{2}", year):
                continue
            by_year.setdefault(year, []).append(row)
        columns = [row[1] for row in hot.execute("PRAGMA table_info(messages)")]
        placeholders = ",".join("?" for _ in columns)
        for year, year_rows in by_year.items():
            year_conn = open_writer(self.data_dir / f"mail-{year}.db")
            before_count = int(year_conn.execute("SELECT count(*) FROM messages").fetchone()[0])
            # Identifiers come only from our own fixed SQLite schema.
            year_conn.executemany(
                f"INSERT OR IGNORE INTO messages({','.join(columns)}) VALUES ({placeholders})",  # noqa: S608
                [tuple(row[column] for column in columns) for row in year_rows],
            )
            message_ids = [str(row["id"]) for row in year_rows]
            for offset in range(0, len(message_ids), 400):
                batch = message_ids[offset : offset + 400]
                marks = ",".join("?" for _ in batch)
                attachments = hot.execute(
                    f"SELECT id,message_id,filename,mimetype,size FROM attachments "  # noqa: S608
                    f"WHERE message_id IN ({marks})",
                    batch,
                ).fetchall()
                year_conn.executemany(
                    """
                    INSERT OR IGNORE INTO attachments(id,message_id,filename,mimetype,size)
                    VALUES (?,?,?,?,?)
                    """,
                    [tuple(item) for item in attachments],
                )
                locations = hot.execute(
                    f"SELECT stable_id,account,folder,uid,uid_validity,flags,"  # noqa: S608
                    f"raw_body_sha256,active,observed_at FROM message_locations "
                    f"WHERE stable_id IN ({marks})",
                    batch,
                ).fetchall()
                year_conn.executemany(
                    """
                    INSERT OR IGNORE INTO message_locations(
                      stable_id,account,folder,uid,uid_validity,flags,
                      raw_body_sha256,active,observed_at
                    ) VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    [tuple(item) for item in locations],
                )
                provider_uids = hot.execute(
                    f"SELECT account,folder,uid_validity,uid,stable_id,flags,"  # noqa: S608
                    f"raw_body_sha256,active,observed_at FROM provider_uid_observations "
                    f"WHERE stable_id IN ({marks})",
                    batch,
                ).fetchall()
                year_conn.executemany(
                    """
                    INSERT OR IGNORE INTO provider_uid_observations(
                      account,folder,uid_validity,uid,stable_id,flags,
                      raw_body_sha256,active,observed_at
                    ) VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    [tuple(item) for item in provider_uids],
                )
                attachment_ids = [str(item["id"]) for item in attachments]
                if attachment_ids:
                    attachment_marks = ",".join("?" for _ in attachment_ids)
                    blob_query = f"SELECT attachment_id,message_id,nonce,ciphertext,content_sha256,content_size,stored_at FROM attachment_blobs WHERE attachment_id IN ({attachment_marks})"  # noqa: S608 - placeholders are generated internally
                    blobs = hot.execute(blob_query, attachment_ids).fetchall()
                    year_conn.executemany(
                        """
                        INSERT OR IGNORE INTO attachment_blobs(
                          attachment_id,message_id,nonce,ciphertext,content_sha256,
                          content_size,stored_at
                        ) VALUES (?,?,?,?,?,?,?)
                        """,
                        [tuple(item) for item in blobs],
                    )
            after_count = int(year_conn.execute("SELECT count(*) FROM messages").fetchone()[0])
            copied += after_count - before_count
            year_conn.commit()
            year_conn.close()
        hot.execute(
            "INSERT INTO shadow_rollover_ledger VALUES (?,?,?,?,?)",
            (scheduled_slot, cutoff.isoformat(), copied, digest, _utc_now()),
        )
        hot.commit()
        hot.close()
        return {"copied": copied, "source_hash": digest, "replayed": False}
