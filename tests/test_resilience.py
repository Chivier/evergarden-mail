"""A database, provider or store fault stays contained and visible.

Covers bounded database connections, dispatcher workers that fail on their
own, heartbeats written outside the shared lock, and long-running OAuth loops
that survive one bad account or record.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import threading
import uuid
from types import SimpleNamespace

import pytest

from apps.mfa_autologin import main as mfa_main
from evergarden import database
from evergarden.approvals.dispatcher import LOOKUP_FAILED, ApprovalDispatcher
from evergarden.approvals.models import Actor, ExecutionState, IntentKind
from evergarden.approvals.service import (
    ApprovalRepository,
    ApprovalService,
    PostgresApprovalRepository,
)
from evergarden.auth.credential_store import CredentialStore, CredentialStoreError, generate_key
from evergarden.auth.maintenance import OAuthMaintenance

HUMAN = Actor("admin", "approval-ui", "approval-ui", True)
AGENT = Actor("agent", "codex", "mcp", False)


def _approved(service: ApprovalService, *, account: str = "gmail", stable_id: str | None = None):
    destination = {"gmail": "[Gmail]/All Mail", "outlook": "Archive"}[account]
    draft = service.prepare(
        kind=IntentKind.ARCHIVE,
        payload={
            "account": account,
            "stable_message_id": stable_id or uuid.uuid4().hex[:24],
            "source_folder": "INBOX",
            "source_uid": 7,
            "source_uid_validity": "777",
            "provider_message_id": "source@example.test",
            "raw_body_sha256": "b" * 64,
            "operation": "archive",
            "destination": destination,
            "copy_preserve_source_fallback": False,
        },
        actor=AGENT,
        lifetime=dt.timedelta(hours=1),
    )
    service.approve(draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=HUMAN)
    return draft


def _dispatcher(service, execute, **kwargs) -> ApprovalDispatcher:
    return ApprovalDispatcher(
        service, execute, kinds=frozenset({IntentKind.ARCHIVE}), host="host-a", **kwargs
    )


def test_connections_bound_connect_query_and_lock_waits(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        database.psycopg, "connect", lambda url, **kwargs: calls.append((url, kwargs))
    )
    database.connect("postgresql://db/evergarden", row_factory=dict)
    database.connect("postgresql://db/evergarden", bounded=False)
    assert calls[0][1] == {
        "connect_timeout": database.CONNECT_TIMEOUT_SECONDS,
        "options": database.BOUNDED_SESSION_OPTIONS,
        "row_factory": dict,
    }
    assert "statement_timeout" in calls[0][1]["options"]
    assert "lock_timeout" in calls[0][1]["options"]
    assert calls[1][1] == {"connect_timeout": database.CONNECT_TIMEOUT_SECONDS}


def test_approval_repository_uses_bounded_connections(fixed_now, monkeypatch) -> None:
    seen = []

    class Unreachable(Exception):
        pass

    def connect(url, **kwargs):
        seen.append(kwargs)
        raise Unreachable("database unavailable")

    monkeypatch.setattr(database.psycopg, "connect", connect)
    repository = PostgresApprovalRepository(
        "postgresql://db/evergarden", key=generate_key(), host_id="host-a"
    )
    draft_id, approval_id = str(uuid.uuid4()), str(uuid.uuid4())
    calls = [
        lambda: repository.add_draft(None),
        lambda: repository.add_approval(None),
        lambda: repository.get_draft(draft_id),
        lambda: repository.get_approval_for_draft(draft_id),
        lambda: repository.get_execution_for_approval(approval_id),
        lambda: repository.approval_rows(fixed_now),
        lambda: repository.consume(approval_id, draft_id, "a" * 64, fixed_now),
        lambda: repository.claim_execution(
            approval_id=approval_id,
            draft_id=draft_id,
            kind=IntentKind.ARCHIVE,
            payload_hash="a" * 64,
            now=fixed_now,
        ),
        lambda: repository.transition_execution(
            approval_id,
            expected=frozenset({ExecutionState.ATTEMPTING}),
            state=ExecutionState.CONFIRMED,
            now=fixed_now,
        ),
    ]
    for call in calls:
        with pytest.raises(Unreachable):
            call()
    assert len(seen) == len(calls)
    for kwargs in seen:
        assert kwargs["connect_timeout"] == database.CONNECT_TIMEOUT_SECONDS
        assert kwargs["options"] == database.BOUNDED_SESSION_OPTIONS


def test_writer_action_lease_uses_a_bounded_connection(monkeypatch) -> None:
    seen = {}

    class Unreachable(Exception):
        pass

    def connect(url, **kwargs):
        seen.update(kwargs)
        raise Unreachable("database unavailable")

    monkeypatch.setattr(database.psycopg, "connect", connect)
    with (
        pytest.raises(Unreachable),
        database.writer_action_lease(
            "postgresql://db/evergarden", action_slot="slot", host="host-a", owner_epoch=2
        ),
    ):
        pass
    assert seen["connect_timeout"] == database.CONNECT_TIMEOUT_SECONDS
    assert seen["options"] == database.BOUNDED_SESSION_OPTIONS


def test_failed_ledger_lookup_keeps_the_message_unresolved_for_the_scan(
    fixed_now, monkeypatch
) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    _approved(service, stable_id="same-message")
    _approved(service, stable_id="same-message")
    executed = []

    def execute(**_kwargs):
        executed.append(1)
        raise RuntimeError("connection lost")

    def lookup_fails(_approval_id):
        raise OSError("database unavailable")

    monkeypatch.setattr(service.repository, "get_execution_for_approval", lookup_fails)
    dispatcher = _dispatcher(service, execute)

    assert dispatcher.run_once() == {LOOKUP_FAILED: 1, "blocked": 1}
    # Neither counts as provider progress, so the loop does not busy-poll.
    assert dispatcher.last_attempted == 0
    assert executed == [1]


def test_one_failed_mailbox_worker_keeps_the_other_mailboxes_results(fixed_now) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    _approved(service, account="gmail")
    _approved(service, account="outlook")
    opened = []
    lock = threading.Lock()

    @contextlib.contextmanager
    def session():
        with lock:
            opened.append(1)
            first = len(opened) == 1
        if first:
            raise OSError("provider session failed")
        yield

    dispatcher = _dispatcher(
        service, lambda **_kwargs: {"state": "CONFIRMED"}, session=session, parallel=2
    )
    assert dispatcher.run_once() == {"worker_failed": 1, "confirmed": 1}
    assert dispatcher.last_item_error_class == "OSError"
    assert dispatcher.last_attempted == 1


def test_one_failed_reconcile_mailbox_does_not_stop_the_others(fixed_now, monkeypatch) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    drafts = [_approved(service, account=account) for account in ("gmail", "outlook")]
    approvals = {draft.draft_id: service.approval_for(draft.draft_id) for draft in drafts}
    monkeypatch.setattr(
        service.repository,
        "reconcilable_executions",
        lambda *_args, **_kwargs: [
            (approvals[draft.draft_id].approval_id, draft.draft_id) for draft in drafts
        ],
    )
    opened = []

    @contextlib.contextmanager
    def session():
        opened.append(1)
        if len(opened) == 1:
            raise OSError("provider session failed")
        yield

    dispatcher = _dispatcher(service, lambda **_kwargs: {"state": "CONFIRMED"}, session=session)
    assert dispatcher.reconcile_once() == {"worker_failed": 1, "reconciled": 1}


def test_heartbeat_writes_outside_the_shared_lock(fixed_now, monkeypatch) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    dispatcher = _dispatcher(service, lambda **_kwargs: {})
    held = []

    def record(**status):
        held.append(dispatcher._lock.locked())

    monkeypatch.setattr(service.repository, "record_dispatcher_status", record)
    dispatcher.heartbeat({"confirmed": 1}, None)
    assert held == [False]
    assert dispatcher.last_result == {"confirmed": 1}


def test_busy_heartbeat_write_is_skipped_but_the_final_one_waits(fixed_now, monkeypatch) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    dispatcher = _dispatcher(service, lambda **_kwargs: {})
    written = []
    monkeypatch.setattr(
        service.repository,
        "record_dispatcher_status",
        lambda **status: written.append(status["last_result"]),
    )

    dispatcher._write_lock.acquire()
    dispatcher.heartbeat({"confirmed": 1}, None)
    assert written == []
    # The in-memory state still moved on, so the next write carries it.
    final = threading.Thread(
        target=dispatcher.heartbeat, args=({"confirmed": 2}, None), kwargs={"wait": True}
    )
    final.start()
    final.join(timeout=0.2)
    assert final.is_alive()
    dispatcher._write_lock.release()
    final.join(timeout=5)
    assert written == [{"confirmed": 2}]


def test_failed_heartbeat_write_is_logged_and_releases_the_writer(fixed_now, monkeypatch) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    dispatcher = _dispatcher(service, lambda **_kwargs: {})

    def unavailable(**_status):
        raise OSError("database unavailable")

    monkeypatch.setattr(service.repository, "record_dispatcher_status", unavailable)
    dispatcher.heartbeat({}, None, wait=True)
    assert not dispatcher._write_lock.locked()


def _maintenance(tmp_path):
    store = CredentialStore(tmp_path / "secrets" / "db", key=generate_key(), host_id="test")
    runtime = SimpleNamespace(store=store, oauth_clients={}, sync_selected=lambda *_a, **_k: None)
    return OAuthMaintenance(runtime, monotonic=lambda: 0.0)


def test_unreadable_pending_record_does_not_hide_other_flows(tmp_path, monkeypatch) -> None:
    maintenance = _maintenance(tmp_path)
    maintenance.store.put("oauth-pending:broken", {"flow": "device_code"})
    real_get = maintenance.store.get

    def get(record_id):
        if record_id == "oauth-pending:broken":
            raise ValueError("record cannot be decrypted")
        return real_get(record_id)

    monkeypatch.setattr(maintenance.store, "get", get)
    assert maintenance._flows() == []
    assert maintenance.step()["failures"] == []


def test_unreadable_store_is_reported_instead_of_ending_the_step(tmp_path, monkeypatch) -> None:
    maintenance = _maintenance(tmp_path)

    def broken():
        raise OSError("credential store unavailable")

    monkeypatch.setattr(maintenance.store, "metadata", broken)
    assert maintenance.step()["failures"] == [{"account": None, "error_class": "OSError"}]


def test_sync_failure_stays_the_reported_cause_when_recording_it_conflicts(
    tmp_path, monkeypatch
) -> None:
    maintenance = _maintenance(tmp_path)
    record_id = maintenance.coordinator._record_id("flow")
    maintenance.store.put(record_id, {"status": "authorized", "account": "work"})

    def sync_fails(*_args, **_kwargs):
        raise TimeoutError("IMAP read timed out")

    maintenance.runtime.sync_selected = sync_fails
    real_put = maintenance.store.put_if_version
    puts = []

    def put_if_version(*args, **kwargs):
        puts.append(1)
        if len(puts) == 2:
            raise CredentialStoreError("credential record changed concurrently")
        return real_put(*args, **kwargs)

    monkeypatch.setattr(maintenance.store, "put_if_version", put_if_version)
    with pytest.raises(TimeoutError):
        maintenance._sync_authorized("flow")


def test_mfa_step_error_is_contained_per_account() -> None:
    def step(account):
        if account == "work":
            raise CredentialStoreError("credential record changed concurrently")
        return {"account": account, "action": "healthy"}

    autologin = SimpleNamespace(step=step)
    assert mfa_main._guarded_step(autologin, "work") == {
        "account": "work",
        "action": "error",
        "error_class": "CredentialStoreError",
    }
    assert mfa_main._guarded_step(autologin, "outlook") == {
        "account": "outlook",
        "action": "healthy",
    }
