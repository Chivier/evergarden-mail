from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit

from evergarden.archive.sqlite_archive import ArchiveWriter
from evergarden.audit.redaction import redact_text
from evergarden.config import Settings
from evergarden.mail.models import load_account_configs
from evergarden.mail.sync import parse_message
from evergarden.private_json import PrivateJsonStore

MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_REQUEST_BYTES = 23 * 1024 * 1024


class BridgeError(RuntimeError):
    pass


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


class BridgeClients:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = PrivateJsonStore(
            settings.thunderbird_bridge_clients_file,
            label="Thunderbird clients",
            error_type=BridgeError,
        )

    def accounts(self):
        # A bridge mailbox keeps ingesting after native sync is enabled for
        # it: the same message stays one record via (stable_id, account), and
        # AccountPolicy keeps the alias receive-only either way. Dropping the
        # paired client on enablement would silently 401 the add-on.
        allowed = self.settings.thunderbird_bridge_account_set
        return {
            item.alias: item
            for item in load_account_configs(
                self.settings.account_config_file, include_disabled=True
            )
            if item.alias in allowed
        }

    def _read(self):
        value = self.store.read_json(max_bytes=65536, default={"clients": []})
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("clients"), list)
            or any(
                not isinstance(item, dict)
                or set(item) != {"account", "address", "sha256", "created_at", "expires_at"}
                or not all(isinstance(field, str) for field in item.values())
                for item in value.get("clients", [])
            )
        ):
            raise BridgeError("bridge client registry is malformed")
        try:
            for item in value["clients"]:
                expiry = dt.datetime.fromisoformat(item["expires_at"])
                if expiry.tzinfo is None:
                    raise ValueError
        except ValueError as exc:
            raise BridgeError("bridge client registry is malformed") from exc
        return value

    def paired_accounts(self) -> set[str]:
        accounts = self.accounts()
        return {
            item["account"]
            for item in self._read()["clients"]
            if item["account"] in accounts
            and item["address"] == accounts[item["account"]].address
            and dt.datetime.fromisoformat(item["expires_at"]) > dt.datetime.now(dt.UTC)
        }

    def pair(self, alias: str) -> dict:
        account = self.accounts().get(alias)
        if account is None:
            raise BridgeError("mailbox is not enabled for Thunderbird bridging")
        token = secrets.token_urlsafe(48)
        with self.store.lock():
            value = self._read()
            # Re-pairing this mailbox revokes its old ingest-only credential.
            entries = [item for item in value["clients"] if item["account"] != alias]
            entries.append(
                {
                    "account": alias,
                    "address": account.address,
                    "sha256": hashlib.sha256(token.encode()).hexdigest(),
                    "created_at": now(),
                    "expires_at": (dt.datetime.now(dt.UTC) + dt.timedelta(days=365)).isoformat(),
                }
            )
            if len(entries) > 32:
                raise BridgeError("too many bridge clients")
            self.store.write_json({"clients": entries})
        resource = urlsplit(str(self.settings.mcp_resource))
        origin = f"{resource.scheme}://{resource.netloc}"
        return {
            "version": 1,
            "endpoint": origin + "/bridge/ingest",
            "account": alias,
            "address": account.address,
            "token": token,
            "paired_at": now(),
        }

    def authenticate(self, token: str) -> dict:
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            raise BridgeError("bridge authentication is required")
        digest = hashlib.sha256(token.encode()).hexdigest()
        allowed = self.accounts()
        for item in self._read()["clients"]:
            if hmac.compare_digest(digest, item["sha256"]):
                account = allowed.get(item["account"])
                if (
                    account is None
                    or account.address != item["address"]
                    or dt.datetime.fromisoformat(item["expires_at"]) <= dt.datetime.now(dt.UTC)
                ):
                    break
                return item
        raise BridgeError("bridge authentication is required")

    def revoke(self, alias: str) -> None:
        with self.store.lock():
            value = self._read()
            self.store.write_json(
                {"clients": [item for item in value["clients"] if item["account"] != alias]}
            )


class BridgeMailbox:
    """Durable receipt journal, archive copies and deduplicated workbench notifications."""

    def __init__(self, data_dir: Path, *, attachment_key: bytes):
        self.path = data_dir / "thunderbird-bridge.db"
        self.archive = ArchiveWriter(data_dir, attachment_key=attachment_key)
        with closing(self.connect()) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL UNIQUE, account TEXT NOT NULL,
                    sender TEXT NOT NULL, subject TEXT NOT NULL,
                    received_at TEXT NOT NULL, notify INTEGER NOT NULL,
                    read_at TEXT
                );
                CREATE TABLE IF NOT EXISTS heartbeats (
                    account TEXT PRIMARY KEY, last_seen TEXT NOT NULL,
                    pending INTEGER NOT NULL, state TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS receipt_notifications ON receipts(notify,seq);
                CREATE INDEX IF NOT EXISTS receipt_unread ON receipts(notify,read_at);
            """)
            conn.commit()

    def connect(self):
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise BridgeError("bridge database path is unsafe")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        conn = sqlite3.connect(self.path, timeout=5)
        self.path.chmod(0o600)
        conn.row_factory = sqlite3.Row
        return conn

    def receive(self, client: dict, payload: dict) -> dict:
        if (
            not isinstance(payload, dict)
            or set(payload) != {"account", "address", "raw_base64", "notify", "read"}
            or payload.get("account") != client["account"]
            or payload.get("address") != client["address"]
        ):
            raise BridgeError("message does not match the paired mailbox")
        if type(payload["notify"]) is not bool or type(payload["read"]) is not bool:
            raise BridgeError("message flags are malformed")
        encoded = payload["raw_base64"]
        if not isinstance(encoded, str) or not 1 <= len(encoded) <= (MAX_RAW_BYTES + 2) // 3 * 4:
            raise BridgeError("message exceeds the 16 MiB bridge limit")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BridgeError("message encoding is malformed") from exc
        if not raw or len(raw) > MAX_RAW_BYTES:
            raise BridgeError("message exceeds the 16 MiB bridge limit")
        record = parse_message(
            account=client["account"],
            folder="INBOX",
            uid=0,
            raw=raw,
            flags=("\\Seen",) if payload["read"] else (),
        )
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            prior = conn.execute(
                "SELECT seq FROM receipts WHERE message_id=?", (record.stable_id,)
            ).fetchone()
            if prior:
                return {"accepted": True, "duplicate": True, "message_id": record.stable_id}
            # The journal serializes bridge writers. If a process dies after
            # archive insertion, resending repairs the missing receipt instead
            # of dropping the notification or importing the message twice.
            if not self.archive.has_message(record.stable_id, record.account):
                self.archive.import_unlocated_records([record])
            conn.execute(
                """INSERT INTO receipts(message_id,account,sender,subject,received_at,notify)
                         VALUES(?,?,?,?,?,?)""",
                (
                    record.stable_id,
                    record.account,
                    redact_text(record.sender_raw)[:320],
                    redact_text(record.subject)[:998],
                    now(),
                    int(payload["notify"]),
                ),
            )
            conn.commit()
        return {"accepted": True, "duplicate": False, "message_id": record.stable_id}

    def heartbeat(self, account: str, *, pending: int, state: str) -> None:
        if (
            type(pending) is not int
            or not 0 <= pending <= 10000
            or state not in {"connected", "retrying", "queue_full", "oversized"}
        ):
            raise BridgeError("bridge heartbeat is malformed")
        with closing(self.connect()) as conn:
            conn.execute(
                """INSERT INTO heartbeats(account,last_seen,pending,state) VALUES(?,?,?,?)
                ON CONFLICT(account) DO UPDATE SET last_seen=excluded.last_seen,
                pending=excluded.pending,state=excluded.state""",
                (account, now(), pending, state),
            )
            conn.commit()

    def status(self, accounts: dict, paired: set[str] | None = None) -> list[dict]:
        with closing(self.connect()) as conn:
            rows = {row["account"]: dict(row) for row in conn.execute("SELECT * FROM heartbeats")}
        cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=3)
        return [
            {
                "account": alias,
                "address": account.address,
                "last_seen": rows.get(alias, {}).get("last_seen"),
                "pending": rows.get(alias, {}).get("pending", 0),
                "paired": paired is None or alias in paired,
                "online": (paired is None or alias in paired)
                and alias in rows
                and dt.datetime.fromisoformat(rows[alias]["last_seen"]) > cutoff,
                "state": rows.get(alias, {}).get("state", "not_connected"),
            }
            for alias, account in accounts.items()
        ]

    def notifications(self, *, after: int = 0) -> dict:
        with closing(self.connect()) as conn:
            items = [
                dict(row)
                for row in conn.execute(
                    """SELECT * FROM receipts
                WHERE notify=1 AND seq>? ORDER BY seq ASC LIMIT 50""",
                    (after,),
                )
            ]
            unread = conn.execute(
                "SELECT count(*) FROM receipts WHERE notify=1 AND read_at IS NULL"
            ).fetchone()[0]
        return {
            "items": items,
            "cursor": max([after, *[item["seq"] for item in items]]),
            "unread_count": unread,
            "has_more": len(items) == 50,
        }

    def acknowledge(self, through: int) -> None:
        with closing(self.connect()) as conn:
            conn.execute(
                "UPDATE receipts SET read_at=? WHERE seq<=? AND read_at IS NULL", (now(), through)
            )
            conn.commit()
