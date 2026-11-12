from __future__ import annotations

import base64
import datetime as dt
import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialStoreError(RuntimeError):
    pass


class CredentialNotFound(CredentialStoreError):
    pass


class CredentialDecryptionError(CredentialStoreError):
    pass


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encode_key(key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("credential key must be 32 bytes")
    return base64.urlsafe_b64encode(key).decode("ascii")


def decode_key(value: str | bytes) -> bytes:
    raw = value.strip().encode("ascii") if isinstance(value, str) else value.strip()
    try:
        decoded = base64.urlsafe_b64decode(raw)
    except (ValueError, TypeError) as exc:
        raise CredentialStoreError("credential key is not valid base64") from exc
    if len(decoded) != 32:
        raise CredentialStoreError("credential key must decode to exactly 32 bytes")
    return decoded


def read_key_file(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CredentialStoreError(
            "credential key must be an existing, non-symlink regular file"
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise CredentialStoreError(
                "credential key must be a regular file with no group/world permissions"
            )
        if not 1 <= info.st_size <= 4096:
            raise CredentialStoreError("credential key size is outside the safety bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(4097)
        if len(value) > 4096:
            raise CredentialStoreError("credential key size is outside the safety bound")
        return decode_key(value)
    finally:
        os.close(descriptor)


class CredentialStore:
    """Host-bound AES-256-GCM credential records in a private SQLite file."""

    def __init__(self, path: Path, *, key: bytes, host_id: str):
        if len(key) != 32:
            raise CredentialStoreError("AES-256-GCM requires a 32-byte key")
        if not host_id or any(ch.isspace() for ch in host_id):
            raise CredentialStoreError("host_id must be a non-empty token")
        self.path = path
        self.host_id = host_id
        self._aes = AESGCM(key)
        self._init_db()

    @classmethod
    def from_key_file(cls, path: Path, *, key_file: Path, host_id: str) -> CredentialStore:
        return cls(path, key=read_key_file(key_file), host_id=host_id)

    def _connect(self) -> sqlite3.Connection:
        if self.path.parent.is_symlink():
            raise CredentialStoreError("credential store directory must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_info = self.path.parent.lstat()
        if not stat.S_ISDIR(parent_info.st_mode):
            raise CredentialStoreError("credential store parent must be a directory")
        self.path.parent.chmod(0o700)
        if self.path.is_symlink():
            raise CredentialStoreError("credential store path must not be a symlink")
        if self.path.exists():
            self._validate_database_file(self.path, label="credential store")
        else:
            try:
                descriptor = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                )
            except OSError as exc:
                raise CredentialStoreError("credential store path is unsafe") from exc
            try:
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        for suffix in ("-wal", "-shm"):
            sidecar = self.path.with_name(self.path.name + suffix)
            if sidecar.is_symlink():
                raise CredentialStoreError("credential store sidecar must not be a symlink")
            # A concurrent WAL checkpoint may remove the sidecar between the
            # existence check and the stat; a vanished sidecar is fine.
            try:
                self._validate_database_file(sidecar, label="credential store sidecar")
            except FileNotFoundError:
                pass
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        self._validate_database_file(self.path, label="credential store")
        for suffix in ("-wal", "-shm"):
            sidecar = self.path.with_name(self.path.name + suffix)
            try:
                sidecar.chmod(0o600)
            except FileNotFoundError:
                pass
        return conn

    @staticmethod
    def _validate_database_file(path: Path, *, label: str) -> None:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise CredentialStoreError(
                f"{label} must be a regular file with no group/world permissions"
            )

    def _init_db(self) -> None:
        with closing(self._connect()) as conn:
            conn.executescript(
                """
            CREATE TABLE IF NOT EXISTS credentials (
                record_id   TEXT PRIMARY KEY,
                host_id     TEXT NOT NULL,
                version     INTEGER NOT NULL,
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credential_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id   TEXT NOT NULL,
                event       TEXT NOT NULL,
                version     INTEGER NOT NULL,
                created_at  TEXT NOT NULL
            );
                """
            )
            conn.commit()

    def _aad(self, record_id: str, version: int) -> bytes:
        return f"evergarden:credential:v1:{self.host_id}:{record_id}:{version}".encode()

    def put(self, record_id: str, value: dict[str, Any]) -> int:
        if not record_id or len(record_id) > 200:
            raise CredentialStoreError("invalid credential record id")
        payload = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT version, created_at FROM credentials WHERE record_id=?", (record_id,)
            ).fetchone()
            version = int(row["version"]) + 1 if row else 1
            created_at = row["created_at"] if row else _utc_now()
            nonce = os.urandom(12)
            ciphertext = self._aes.encrypt(nonce, payload, self._aad(record_id, version))
            now = _utc_now()
            conn.execute(
                """
            INSERT INTO credentials(record_id,host_id,version,nonce,ciphertext,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(record_id) DO UPDATE SET
                host_id=excluded.host_id, version=excluded.version,
                nonce=excluded.nonce, ciphertext=excluded.ciphertext,
                updated_at=excluded.updated_at
                """,
                (record_id, self.host_id, version, nonce, ciphertext, created_at, now),
            )
            conn.execute(
                "INSERT INTO credential_events(record_id,event,version,created_at) VALUES (?,?,?,?)",
                (record_id, "created" if version == 1 else "rotated", version, now),
            )
            conn.commit()
        return version

    def get_with_version(self, record_id: str) -> tuple[dict[str, Any], int]:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT host_id,version,nonce,ciphertext FROM credentials WHERE record_id=?",
                (record_id,),
            ).fetchone()
        if not row:
            raise CredentialNotFound(f"credential record not found: {record_id}")
        if row["host_id"] != self.host_id:
            raise CredentialDecryptionError("credential belongs to a different host")
        try:
            payload = self._aes.decrypt(
                row["nonce"], row["ciphertext"], self._aad(record_id, int(row["version"]))
            )
        except InvalidTag as exc:
            raise CredentialDecryptionError("credential authentication failed") from exc
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CredentialDecryptionError("credential payload is invalid") from exc
        if not isinstance(value, dict):
            raise CredentialDecryptionError("credential payload must be an object")
        return value, int(row["version"])

    def get(self, record_id: str) -> dict[str, Any]:
        return self.get_with_version(record_id)[0]

    def put_if_version(
        self,
        record_id: str,
        *,
        expected_version: int,
        value: dict[str, Any],
        event: str = "claimed",
    ) -> int:
        """Atomically update a record only if no competing process changed it."""
        payload = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT host_id,version FROM credentials WHERE record_id=?", (record_id,)
            ).fetchone()
            if not row or row["host_id"] != self.host_id or int(row["version"]) != expected_version:
                conn.rollback()
                raise CredentialStoreError("credential record changed concurrently")
            version = expected_version + 1
            nonce = os.urandom(12)
            ciphertext = self._aes.encrypt(nonce, payload, self._aad(record_id, version))
            now = _utc_now()
            updated = conn.execute(
                """
                UPDATE credentials SET version=?,nonce=?,ciphertext=?,updated_at=?
                WHERE record_id=? AND host_id=? AND version=?
                """,
                (
                    version,
                    nonce,
                    ciphertext,
                    now,
                    record_id,
                    self.host_id,
                    expected_version,
                ),
            ).rowcount
            if updated != 1:
                conn.rollback()
                raise CredentialStoreError("credential record changed concurrently")
            conn.execute(
                "INSERT INTO credential_events(record_id,event,version,created_at) VALUES (?,?,?,?)",
                (record_id, event, version, now),
            )
            conn.commit()
        return version

    def delete(self, record_id: str, *, event: str = "deleted") -> bool:
        """Remove a record and its per-version events, keeping one final event.

        Meant for ephemeral records (pending OAuth state); long-lived
        credentials are rotated, not deleted.
        """
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT host_id,version FROM credentials WHERE record_id=?", (record_id,)
            ).fetchone()
            if not row or row["host_id"] != self.host_id:
                conn.rollback()
                return False
            conn.execute("DELETE FROM credentials WHERE record_id=?", (record_id,))
            conn.execute("DELETE FROM credential_events WHERE record_id=?", (record_id,))
            conn.execute(
                "INSERT INTO credential_events(record_id,event,version,created_at) VALUES (?,?,?,?)",
                (record_id, event, int(row["version"]), _utc_now()),
            )
            conn.commit()
        return True

    def create_if_absent(
        self,
        record_id: str,
        *,
        value: dict[str, Any],
        event: str = "created",
    ) -> int:
        """Atomically create a record without overwriting a concurrent writer."""
        if not record_id or len(record_id) > 200:
            raise CredentialStoreError("invalid credential record id")
        payload = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM credentials WHERE record_id=?", (record_id,)).fetchone():
                conn.rollback()
                raise CredentialStoreError("credential record changed concurrently")
            version = 1
            nonce = os.urandom(12)
            ciphertext = self._aes.encrypt(nonce, payload, self._aad(record_id, version))
            now = _utc_now()
            conn.execute(
                """
                INSERT INTO credentials(
                  record_id,host_id,version,nonce,ciphertext,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?)
                """,
                (record_id, self.host_id, version, nonce, ciphertext, now, now),
            )
            conn.execute(
                "INSERT INTO credential_events(record_id,event,version,created_at) VALUES (?,?,?,?)",
                (record_id, event, version, now),
            )
            conn.commit()
        return version

    def rekey(self, new_key: bytes) -> None:
        """Re-encrypt every record under a new 256-bit key in one transaction."""
        if len(new_key) != 32:
            raise CredentialStoreError("AES-256-GCM requires a 32-byte key")
        replacement = AESGCM(new_key)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT record_id,host_id,version,nonce,ciphertext FROM credentials ORDER BY record_id"
            ).fetchall()
            now = _utc_now()
            for row in rows:
                record_id = str(row["record_id"])
                if row["host_id"] != self.host_id:
                    raise CredentialDecryptionError("credential belongs to a different host")
                try:
                    plaintext = self._aes.decrypt(
                        row["nonce"],
                        row["ciphertext"],
                        self._aad(record_id, int(row["version"])),
                    )
                except InvalidTag as exc:
                    raise CredentialDecryptionError("credential authentication failed") from exc
                version = int(row["version"]) + 1
                nonce = os.urandom(12)
                ciphertext = replacement.encrypt(nonce, plaintext, self._aad(record_id, version))
                conn.execute(
                    "UPDATE credentials SET version=?,nonce=?,ciphertext=?,updated_at=? WHERE record_id=?",
                    (version, nonce, ciphertext, now, record_id),
                )
                conn.execute(
                    "INSERT INTO credential_events(record_id,event,version,created_at) VALUES (?,?,?,?)",
                    (record_id, "rekeyed", version, now),
                )
            conn.commit()
        self._aes = replacement

    def metadata(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT record_id,host_id,version,created_at,updated_at FROM credentials ORDER BY record_id"
            ).fetchall()
        return [dict(row) for row in rows]
