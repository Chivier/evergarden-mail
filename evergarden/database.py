from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import pathlib
import time
import uuid

import psycopg
from psycopg.rows import dict_row

from evergarden.audit.redaction import redact
from evergarden.automations.fence import LeaseToken

CONNECT_TIMEOUT_SECONDS = 5
# Bound query and lock waits so an unavailable or locked database cannot
# indefinitely occupy a request, a dispatcher thread or a scheduled job.
BOUNDED_SESSION_OPTIONS = "-c statement_timeout=15000 -c lock_timeout=5000"


def connect(database_url: str, *, bounded: bool = True, **kwargs) -> psycopg.Connection:
    """Open a connection that gives up instead of hanging on the database.

    ``bounded=False`` keeps only the connect timeout, for whole-table work such
    as migrations and audit-chain verification.
    """
    if bounded:
        kwargs.setdefault("options", BOUNDED_SESSION_OPTIONS)
    return psycopg.connect(database_url, connect_timeout=CONNECT_TIMEOUT_SECONDS, **kwargs)


def advisory_key(job_id: str, scheduled_slot: str) -> int:
    raw = hashlib.blake2b(f"{job_id}\0{scheduled_slot}".encode(), digest_size=8).digest()
    return int.from_bytes(raw, "big", signed=True)


def apply_migrations(database_url: str, directory: pathlib.Path) -> list[str]:
    applied: list[str] = []
    with connect(database_url, bounded=False, autocommit=True) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        existing = {row[0] for row in conn.execute("SELECT name FROM schema_migrations")}
        for path in sorted(directory.glob("*.sql")):
            if path.name in existing:
                continue
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations(name) VALUES (%s)", (path.name,))
            applied.append(path.name)
    return applied


class DuplicateJobRun(RuntimeError):
    pass


class WriterLeaseUnavailable(RuntimeError):
    """The approved-action lease is held elsewhere or writer control is inactive."""


@contextlib.contextmanager
def writer_action_lease(
    database_url: str,
    *,
    action_slot: str,
    host: str,
    owner_epoch: int,
):
    """Hold a Postgres session lease for one approved provider action."""
    conn = connect(database_url, row_factory=dict_row)
    key = advisory_key("approved-mail-action", action_slot)
    locked = False
    try:
        lock_row = conn.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone()
        locked = bool(lock_row["pg_try_advisory_lock"])
        if not locked:
            raise WriterLeaseUnavailable("approved mail action lease is already held")
        runtime = conn.execute(
            "SELECT active_writer,writer_epoch,side_effects_enabled "
            "FROM runtime_control WHERE singleton=TRUE FOR SHARE"
        ).fetchone()
        if (
            not runtime
            or str(runtime["active_writer"]) != host
            or int(runtime["writer_epoch"]) != owner_epoch
            or not bool(runtime["side_effects_enabled"])
        ):
            raise WriterLeaseUnavailable("database writer control does not authorize mail actions")
        yield LeaseToken(
            job_id="approved-mail-action",
            scheduled_slot=action_slot,
            owner_host=host,
            writer_epoch=owner_epoch,
            nonce=str(uuid.uuid4()),
        )
    finally:
        if locked:
            with contextlib.suppress(psycopg.Error):
                conn.execute("SELECT pg_advisory_unlock(%s)", (key,))
        conn.close()


def transition_runtime_control(
    database_url: str,
    *,
    expected_writer: str,
    expected_epoch: int,
    expected_side_effects: bool,
    new_writer: str,
    new_epoch: int,
    new_side_effects: bool,
) -> dict[str, object]:
    """Compare-and-swap the singleton writer fence in one transaction."""
    if new_epoch <= expected_epoch:
        raise ValueError("writer handoff must advance the writer epoch")
    with connect(database_url, row_factory=dict_row) as conn:
        with conn.transaction():
            current = conn.execute(
                "SELECT active_writer,writer_epoch,side_effects_enabled "
                "FROM runtime_control WHERE singleton=TRUE FOR UPDATE"
            ).fetchone()
            expected = (expected_writer, expected_epoch, expected_side_effects)
            observed = (
                str(current["active_writer"]) if current else "",
                int(current["writer_epoch"]) if current else 0,
                bool(current["side_effects_enabled"]) if current else False,
            )
            if observed != expected:
                raise RuntimeError("database writer control changed before handoff")
            conn.execute(
                "UPDATE runtime_control SET active_writer=%s,writer_epoch=%s,"
                "side_effects_enabled=%s,updated_at=now() WHERE singleton=TRUE",
                (new_writer, new_epoch, new_side_effects),
            )
    return {
        "previous_writer": expected_writer,
        "previous_epoch": expected_epoch,
        "previous_side_effects": expected_side_effects,
        "active_writer": new_writer,
        "writer_epoch": new_epoch,
        "side_effects_enabled": new_side_effects,
    }


class WriterControlConflict(RuntimeError):
    """The database names a different writer or a newer epoch than this host's settings."""


def reconcile_runtime_control(
    database_url: str,
    *,
    host: str,
    active_writer: str,
    writer_epoch: int,
    side_effects_enabled: bool,
) -> dict[str, object]:
    """Bring the database writer fence in line with this host's settings.

    The singleton ``runtime_control`` row is the authority every provider write
    checks under a lease. A fresh database starts with no writer. When this
    host is the configured writer, the row is set to this host, its epoch and
    its side-effect switch, so enabling or disabling writes is one settings
    change. The row is never taken from another named writer and its epoch
    never moves backwards: those cases need a deliberate operator decision and
    raise ``WriterControlConflict`` without changing anything. A host that is
    not the configured writer leaves the row untouched.
    """
    with connect(database_url, row_factory=dict_row) as conn:
        with conn.transaction():
            current = conn.execute(
                "SELECT active_writer,writer_epoch,side_effects_enabled "
                "FROM runtime_control WHERE singleton=TRUE FOR UPDATE"
            ).fetchone()
            if current is None:
                raise WriterControlConflict("database writer control row is missing")
            observed = {
                "active_writer": str(current["active_writer"]),
                "writer_epoch": int(current["writer_epoch"]),
                "side_effects_enabled": bool(current["side_effects_enabled"]),
            }
            if active_writer != host:
                return {**observed, "changed": False}
            desired = {
                "active_writer": host,
                "writer_epoch": writer_epoch,
                "side_effects_enabled": side_effects_enabled,
            }
            if observed == desired:
                return {**observed, "changed": False}
            if observed["active_writer"] not in {host, "none"}:
                raise WriterControlConflict(
                    "database writer control names another writer host; "
                    "change it deliberately before enabling this one"
                )
            if writer_epoch < observed["writer_epoch"]:
                raise WriterControlConflict(
                    "configured writer epoch is older than the database writer epoch"
                )
            conn.execute(
                "UPDATE runtime_control SET active_writer=%s,writer_epoch=%s,"
                "side_effects_enabled=%s,updated_at=now() WHERE singleton=TRUE",
                (host, writer_epoch, side_effects_enabled),
            )
    return {**desired, "changed": True, "previous": observed}


def _audit_event_hash(
    *,
    event_id: str,
    event_type: str,
    actor: str,
    client_id: str | None,
    outcome: str,
    metadata: dict,
    previous_hash: str,
    created_at: dt.datetime,
) -> str:
    canonical = json.dumps(
        {
            "event_id": event_id,
            "event_type": event_type,
            "actor": actor,
            "client_id": client_id,
            "outcome": outcome,
            "metadata": metadata,
            "previous_hash": previous_hash,
            "created_at": created_at.isoformat(timespec="microseconds"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def append_audit_event(
    database_url: str,
    *,
    event_type: str,
    actor: str,
    client_id: str | None,
    outcome: str,
    metadata: dict,
) -> str:
    """Append one redacted event to a serialized tamper-evident hash chain."""
    event_id = uuid.uuid4()
    safe_metadata = redact(metadata)
    with connect(database_url) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (advisory_key("audit", "chain-v1"),))
        row = conn.execute(
            "SELECT event_hash,created_at FROM audit_events "
            "ORDER BY created_at DESC,event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(row[0]) if row else "0" * 64
        created_at = dt.datetime.now(dt.UTC)
        if row and created_at <= row[1]:
            created_at = row[1] + dt.timedelta(microseconds=1)
        event_hash = _audit_event_hash(
            event_id=str(event_id),
            event_type=event_type,
            actor=actor,
            client_id=client_id,
            outcome=outcome,
            metadata=safe_metadata,
            previous_hash=previous_hash,
            created_at=created_at,
        )
        conn.execute(
            """
            INSERT INTO audit_events(
              event_id,event_type,actor,client_id,outcome,metadata,
              previous_hash,event_hash,created_at
            ) VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)
            """,
            (
                event_id,
                event_type,
                actor,
                client_id,
                outcome,
                json.dumps(safe_metadata, ensure_ascii=False, sort_keys=True),
                previous_hash,
                event_hash,
                created_at,
            ),
        )
        conn.commit()
    return str(event_id)


def verify_audit_chain(database_url: str) -> dict[str, int | bool | str]:
    previous = "0" * 64
    count = 0
    with connect(database_url, bounded=False, row_factory=dict_row) as conn:
        rows = conn.execute(
            """
            SELECT event_id,event_type,actor,client_id,outcome,metadata,
                   previous_hash,event_hash,created_at
            FROM audit_events ORDER BY created_at,event_id
            """
        ).fetchall()
    for row in rows:
        expected = _audit_event_hash(
            event_id=str(row["event_id"]),
            event_type=str(row["event_type"]),
            actor=str(row["actor"]),
            client_id=str(row["client_id"]) if row["client_id"] is not None else None,
            outcome=str(row["outcome"]),
            metadata=row["metadata"],
            previous_hash=previous,
            created_at=row["created_at"],
        )
        if row["previous_hash"] != previous or row["event_hash"] != expected:
            return {"valid": False, "events": count, "head": previous}
        previous = str(row["event_hash"])
        count += 1
    return {"valid": True, "events": count, "head": previous}


def mail_operations_status(database_url: str) -> dict:
    """Return mail-only operational counts; never payloads, recipients, or content."""
    with connect(database_url, row_factory=dict_row) as conn:
        runtime = conn.execute(
            "SELECT active_writer,writer_epoch,side_effects_enabled,updated_at "
            "FROM runtime_control WHERE singleton=TRUE"
        ).fetchone()
        outcomes = {
            str(row["outcome"]): int(row["count"])
            for row in conn.execute(
                "SELECT outcome,count(*) AS count FROM job_runs "
                "WHERE job_id IN ('archive-sync','oauth-watchdog','weekly-rollover',"
                "'cold-export') GROUP BY outcome"
            )
        }
        mail_actions = {
            str(row["state"]): int(row["count"])
            for row in conn.execute(
                "SELECT state,count(*) AS count FROM mail_action_ledger GROUP BY state"
            )
        }
        latest = [
            {
                "job_id": str(row["job_id"]),
                "scheduled_slot": str(row["scheduled_slot"]),
                "outcome": str(row["outcome"]),
                "duration_ms": int(row["duration_ms"]) if row["duration_ms"] is not None else None,
            }
            for row in conn.execute(
                """
                SELECT DISTINCT ON (job_id) job_id,scheduled_slot,outcome,duration_ms
                FROM job_runs
                WHERE job_id IN ('archive-sync','oauth-watchdog','weekly-rollover','cold-export')
                ORDER BY job_id,created_at DESC
                """
            )
        ]
    return {
        "active_writer": runtime["active_writer"],
        "writer_epoch": int(runtime["writer_epoch"]),
        "side_effects_enabled": bool(runtime["side_effects_enabled"]),
        "runtime_updated_at": runtime["updated_at"].isoformat(),
        "job_outcomes": dict(sorted(outcomes.items())),
        "mail_action_states": dict(sorted(mail_actions.items())),
        "latest_jobs": latest,
    }


class JobLease:
    def __init__(
        self,
        *,
        database_url: str,
        job_id: str,
        scheduled_slot: str,
        host: str,
        owner_epoch: int,
    ):
        self.database_url = database_url
        self.job_id = job_id
        self.scheduled_slot = scheduled_slot
        self.host = host
        self.owner_epoch = owner_epoch
        self.run_id = uuid.uuid4()
        self.idempotency_key = hashlib.sha256(
            f"{job_id}\0{scheduled_slot}\0{owner_epoch}".encode()
        ).hexdigest()
        self.conn: psycopg.Connection | None = None
        self.started = 0.0

    def __enter__(self) -> JobLease:
        self.conn = connect(self.database_url, row_factory=dict_row)
        key = advisory_key(self.job_id, self.scheduled_slot)
        locked = self.conn.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone()[
            "pg_try_advisory_lock"
        ]
        if not locked:
            self.conn.close()
            self.conn = None
            raise DuplicateJobRun("job lease is already held")
        row = self.conn.execute(
            "SELECT active_writer,writer_epoch,side_effects_enabled FROM runtime_control WHERE singleton=TRUE"
        ).fetchone()
        if not row or int(row["writer_epoch"]) != self.owner_epoch:
            self._close()
            raise DuplicateJobRun("job owner epoch does not match runtime control")
        try:
            inserted = self.conn.execute(
                """
                INSERT INTO job_runs(run_id,job_id,scheduled_slot,host,owner_epoch,idempotency_key,outcome)
                VALUES (%s,%s,%s,%s,%s,%s,'RUNNING')
                ON CONFLICT DO NOTHING RETURNING run_id
                """,
                (
                    self.run_id,
                    self.job_id,
                    self.scheduled_slot,
                    self.host,
                    self.owner_epoch,
                    self.idempotency_key,
                ),
            ).fetchone()
            self.conn.commit()
        except psycopg.errors.UniqueViolation as exc:
            self.conn.rollback()
            self._close()
            raise DuplicateJobRun("scheduled slot already has an authoritative run") from exc
        if inserted is None:
            self._close()
            raise DuplicateJobRun("scheduled slot already has an authoritative run")
        self.started = time.monotonic()
        return self

    def finish(self, outcome: str) -> None:
        if not self.conn:
            raise RuntimeError("job lease is not active")
        duration = int((time.monotonic() - self.started) * 1000)
        self.conn.execute(
            "UPDATE job_runs SET outcome=%s,duration_ms=%s,updated_at=now() WHERE run_id=%s",
            (outcome, duration, self.run_id),
        )
        self.conn.commit()

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.conn:
            outcome = "FAILED" if exc else "SUCCESS"
            current = self.conn.execute(
                "SELECT outcome FROM job_runs WHERE run_id=%s", (self.run_id,)
            ).fetchone()
            if current and current["outcome"] == "RUNNING":
                self.finish(outcome)
        self._close()

    def _close(self) -> None:
        if self.conn:
            with contextlib.suppress(psycopg.Error):
                self.conn.execute(
                    "SELECT pg_advisory_unlock(%s)",
                    (advisory_key(self.job_id, self.scheduled_slot),),
                )
            self.conn.close()
            self.conn = None
