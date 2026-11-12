from __future__ import annotations

import contextlib
import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

from evergarden import database
from evergarden.database import DuplicateJobRun, JobLease


class Cursor:
    def __init__(self, *, one: Any = None, rows: list[Any] | None = None):
        self.one = one
        self.rows = rows or []

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.rows

    def __iter__(self):
        return iter(self.rows)


class Connection:
    def __init__(self, handler):
        self.handler = handler
        self.calls: list[tuple[str, Any]] = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def execute(self, sql: str, params=None):
        self.calls.append((sql, params))
        return self.handler(sql, params)

    def transaction(self):
        return contextlib.nullcontext()

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_apply_migrations_is_ordered_and_skips_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "002_second.sql").write_text("SELECT 2")
    (migrations / "001_first.sql").write_text("SELECT 1")

    def handler(sql: str, _params):
        if sql == "SELECT name FROM schema_migrations":
            return Cursor(rows=[("001_first.sql",)])
        return Cursor()

    connection = Connection(handler)
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: connection)
    assert database.apply_migrations("postgresql://test", migrations) == ["002_second.sql"]
    statements = [sql for sql, _params in connection.calls]
    assert "SELECT 2" in statements
    assert "SELECT 1" not in statements
    assert any("INSERT INTO schema_migrations" in sql for sql in statements)


def test_writer_action_lease_checks_lock_and_runtime_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def valid_handler(sql: str, _params):
        if "pg_try_advisory_lock" in sql:
            return Cursor(one={"pg_try_advisory_lock": True})
        if "FROM runtime_control" in sql:
            return Cursor(
                one={"active_writer": "host-a", "writer_epoch": 7, "side_effects_enabled": True}
            )
        return Cursor(one={})

    valid = Connection(valid_handler)
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: valid)
    with database.writer_action_lease(
        "postgresql://test", action_slot="approval-1", host="host-a", owner_epoch=7
    ) as lease:
        assert lease.owner_host == "host-a"
        assert lease.writer_epoch == 7
        assert lease.job_id == "approved-mail-action"
    assert valid.closed is True
    assert any("pg_advisory_unlock" in sql for sql, _params in valid.calls)

    locked = Connection(
        lambda sql, _params: (
            Cursor(one={"pg_try_advisory_lock": False})
            if "pg_try_advisory_lock" in sql
            else Cursor()
        )
    )
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: locked)
    with pytest.raises(RuntimeError, match="already held"):
        with database.writer_action_lease(
            "postgresql://test", action_slot="approval-1", host="host-a", owner_epoch=7
        ):
            raise AssertionError("lease must not be yielded")
    assert locked.closed is True

    invalid = Connection(
        lambda sql, _params: (
            Cursor(one={"pg_try_advisory_lock": True})
            if "pg_try_advisory_lock" in sql
            else Cursor(
                one={
                    "active_writer": "host-b",
                    "writer_epoch": 6,
                    "side_effects_enabled": False,
                }
            )
        )
    )
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: invalid)
    with pytest.raises(RuntimeError, match="does not authorize"):
        with database.writer_action_lease(
            "postgresql://test", action_slot="approval-1", host="host-a", owner_epoch=7
        ):
            raise AssertionError("lease must not be yielded")


def _control_connection(monkeypatch: pytest.MonkeyPatch, current: dict | None) -> Connection:
    def handler(sql: str, params):
        if "FROM runtime_control" in sql:
            return Cursor(one=None if current is None else dict(current))
        if "UPDATE runtime_control" in sql:
            current.update(
                active_writer=params[0],
                writer_epoch=params[1],
                side_effects_enabled=params[2],
            )
        return Cursor()

    connection = Connection(handler)
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: connection)
    return connection


def _reconcile(**overrides):
    values = {
        "host": "host-a",
        "active_writer": "host-a",
        "writer_epoch": 1,
        "side_effects_enabled": True,
        **overrides,
    }
    return database.reconcile_runtime_control("postgresql://test", **values)


def test_reconcile_claims_an_unowned_fresh_database_for_the_configured_writer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = {"active_writer": "none", "writer_epoch": 1, "side_effects_enabled": False}
    _control_connection(monkeypatch, current)
    result = _reconcile()
    assert result["changed"] is True
    assert result["previous"]["active_writer"] == "none"
    assert current == {"active_writer": "host-a", "writer_epoch": 1, "side_effects_enabled": True}

    # Turning the switch off again is followed by the database row.
    assert _reconcile(side_effects_enabled=False)["changed"] is True
    assert current["side_effects_enabled"] is False
    # Raising the configured epoch fences out older processes.
    assert _reconcile(writer_epoch=2)["writer_epoch"] == 2
    assert current["writer_epoch"] == 2


def test_reconcile_leaves_a_matching_row_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    current = {"active_writer": "host-a", "writer_epoch": 2, "side_effects_enabled": True}
    connection = _control_connection(monkeypatch, current)
    result = _reconcile(writer_epoch=2)
    assert result == {**current, "changed": False}
    assert not any("UPDATE runtime_control" in sql for sql, _params in connection.calls)


def test_reconcile_never_steals_writes_or_rewinds_the_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = {"active_writer": "host-b", "writer_epoch": 1, "side_effects_enabled": True}
    connection = _control_connection(monkeypatch, current)
    with pytest.raises(database.WriterControlConflict, match="another writer"):
        _reconcile()
    newer = {"active_writer": "host-a", "writer_epoch": 3, "side_effects_enabled": False}
    connection = _control_connection(monkeypatch, newer)
    with pytest.raises(database.WriterControlConflict, match="older"):
        _reconcile(writer_epoch=2)
    assert not any("UPDATE runtime_control" in sql for sql, _params in connection.calls)
    _control_connection(monkeypatch, None)
    with pytest.raises(database.WriterControlConflict, match="missing"):
        _reconcile()


def test_reconcile_from_a_non_writer_host_only_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    current = {"active_writer": "host-b", "writer_epoch": 4, "side_effects_enabled": True}
    connection = _control_connection(monkeypatch, current)
    assert _reconcile(active_writer="host-b", side_effects_enabled=False) == {
        **current,
        "changed": False,
    }
    assert _reconcile(active_writer="none", side_effects_enabled=False)["changed"] is False
    assert not any("UPDATE runtime_control" in sql for sql, _params in connection.calls)


def test_runtime_control_transition_is_compare_and_swap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = {"active_writer": "host-b", "writer_epoch": 1, "side_effects_enabled": False}

    def handler(sql: str, params):
        if "FROM runtime_control" in sql:
            return Cursor(one=current)
        if "UPDATE runtime_control" in sql:
            current.update(
                active_writer=params[0],
                writer_epoch=params[1],
                side_effects_enabled=params[2],
            )
        return Cursor()

    connection = Connection(handler)
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: connection)
    result = database.transition_runtime_control(
        "postgresql://test",
        expected_writer="host-b",
        expected_epoch=1,
        expected_side_effects=False,
        new_writer="host-a",
        new_epoch=2,
        new_side_effects=True,
    )
    assert result["active_writer"] == "host-a"
    assert result["writer_epoch"] == 2
    assert current == {
        "active_writer": "host-a",
        "writer_epoch": 2,
        "side_effects_enabled": True,
    }
    with pytest.raises(ValueError, match="advance"):
        database.transition_runtime_control(
            "postgresql://test",
            expected_writer="host-a",
            expected_epoch=2,
            expected_side_effects=True,
            new_writer="none",
            new_epoch=2,
            new_side_effects=False,
        )

    stale = Connection(
        lambda sql, _params: (
            Cursor(
                one={"active_writer": "host-b", "writer_epoch": 1, "side_effects_enabled": False}
            )
            if "FROM runtime_control" in sql
            else Cursor()
        )
    )
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: stale)
    with pytest.raises(RuntimeError, match="changed"):
        database.transition_runtime_control(
            "postgresql://test",
            expected_writer="host-a",
            expected_epoch=2,
            expected_side_effects=True,
            new_writer="none",
            new_epoch=3,
            new_side_effects=False,
        )


def test_append_and_verify_audit_chain_with_tamper_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous_time = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=5)
    inserted: list[tuple] = []

    def append_handler(sql: str, params):
        if "ORDER BY created_at DESC" in sql:
            return Cursor(one=("a" * 64, previous_time))
        if "INSERT INTO audit_events" in sql:
            inserted.append(params)
        return Cursor()

    append_connection = Connection(append_handler)
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: append_connection)
    event_id = database.append_audit_event(
        "postgresql://test",
        event_type="mcp.tool",
        actor="operator",
        client_id="codex",
        outcome="SUCCESS",
        metadata={"password": "never-store", "tool": "list_recent"},
    )
    assert event_id
    assert append_connection.commits == 1
    assert json.loads(inserted[0][5])["password"] == "[REDACTED]"
    assert inserted[0][-1] > previous_time

    created = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC)
    row = {
        "event_id": "event-1",
        "event_type": "mcp.tool",
        "actor": "operator",
        "client_id": None,
        "outcome": "SUCCESS",
        "metadata": {"tool": "count_mail"},
        "previous_hash": "0" * 64,
        "created_at": created,
    }
    row["event_hash"] = database._audit_event_hash(
        event_id=row["event_id"],
        event_type=row["event_type"],
        actor=row["actor"],
        client_id=None,
        outcome=row["outcome"],
        metadata=row["metadata"],
        previous_hash=row["previous_hash"],
        created_at=created,
    )

    valid = Connection(lambda _sql, _params: Cursor(rows=[row]))
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: valid)
    assert database.verify_audit_chain("postgresql://test") == {
        "valid": True,
        "events": 1,
        "head": row["event_hash"],
    }
    tampered = Connection(lambda _sql, _params: Cursor(rows=[{**row, "event_hash": "f" * 64}]))
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: tampered)
    assert database.verify_audit_chain("postgresql://test") == {
        "valid": False,
        "events": 0,
        "head": "0" * 64,
    }


def test_mail_operations_status_returns_only_mail_aggregates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    updated = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC)

    def handler(sql: str, _params):
        if "FROM runtime_control" in sql:
            return Cursor(
                one={
                    "active_writer": "host-b",
                    "writer_epoch": 3,
                    "side_effects_enabled": False,
                    "updated_at": updated,
                }
            )
        if "FROM job_runs" in sql and "GROUP BY outcome" in sql:
            return Cursor(rows=[{"outcome": "SUCCESS", "count": 4}])
        if "FROM mail_action_ledger GROUP" in sql:
            return Cursor(rows=[{"state": "CONFIRMED", "count": 1}])
        if "SELECT DISTINCT ON" in sql:
            return Cursor(
                rows=[
                    {
                        "job_id": "archive-sync",
                        "scheduled_slot": "2026-08-18T12:03:00Z",
                        "outcome": "SUCCESS",
                        "duration_ms": None,
                    }
                ]
            )
        raise AssertionError(sql)

    connection = Connection(handler)
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: connection)
    value = database.mail_operations_status("postgresql://test")
    assert value["active_writer"] == "host-b"
    assert value["job_outcomes"] == {"SUCCESS": 4}
    assert value["mail_action_states"] == {"CONFIRMED": 1}
    assert value["latest_jobs"][0]["duration_ms"] is None
    assert "outbox_states" not in value
    assert "delivery_states" not in value


def test_job_lease_success_and_fail_closed_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"outcome": "RUNNING"}

    def handler(sql: str, params):
        if "pg_try_advisory_lock" in sql:
            return Cursor(one={"pg_try_advisory_lock": True})
        if "FROM runtime_control" in sql:
            return Cursor(one={"active_writer": "host-b", "writer_epoch": 5})
        if "INSERT INTO job_runs" in sql:
            return Cursor(one={"run_id": "test-run"})
        if "SELECT outcome FROM job_runs" in sql:
            return Cursor(one={"outcome": state["outcome"]})
        if "UPDATE job_runs" in sql:
            state["outcome"] = params[0]
            return Cursor()
        return Cursor()

    connection = Connection(handler)
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: connection)
    with JobLease(
        database_url="postgresql://test",
        job_id="archive-sync",
        scheduled_slot="2026-08-18T12:03:00Z",
        host="host-a",
        owner_epoch=5,
    ) as lease:
        assert len(lease.idempotency_key) == 64
    assert state["outcome"] == "SUCCESS"
    assert connection.closed is True

    unlocked = Connection(
        lambda sql, _params: (
            Cursor(one={"pg_try_advisory_lock": False})
            if "pg_try_advisory_lock" in sql
            else Cursor()
        )
    )
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: unlocked)
    with pytest.raises(DuplicateJobRun, match="already held"):
        with JobLease(
            database_url="postgresql://test",
            job_id="archive-sync",
            scheduled_slot="slot",
            host="host-a",
            owner_epoch=5,
        ):
            raise AssertionError("must not enter")

    stale = Connection(
        lambda sql, _params: (
            Cursor(one={"pg_try_advisory_lock": True})
            if "pg_try_advisory_lock" in sql
            else (
                Cursor(one={"active_writer": "host-b", "writer_epoch": 4})
                if "FROM runtime_control" in sql
                else Cursor()
            )
        )
    )
    monkeypatch.setattr(database.psycopg, "connect", lambda *_args, **_kwargs: stale)
    with pytest.raises(DuplicateJobRun, match="epoch"):
        with JobLease(
            database_url="postgresql://test",
            job_id="archive-sync",
            scheduled_slot="slot",
            host="host-a",
            owner_epoch=5,
        ):
            raise AssertionError("must not enter")
