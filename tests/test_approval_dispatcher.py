from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from account_fixtures import TEST_ACCOUNTS
from fastapi.testclient import TestClient

from apps.mcp.main import create_app
from evergarden.approvals import dispatcher as dispatcher_module
from evergarden.approvals.dispatcher import ApprovalDispatcher
from evergarden.approvals.models import Actor, Approval, ApprovalSource, ExecutionState, IntentKind
from evergarden.approvals.service import (
    ApprovalError,
    ApprovalRepository,
    ApprovalService,
    ProviderDefinitelyRejected,
    ProviderNotAttempted,
    ProviderOutcomeUnknown,
    ProviderPartialOutcome,
    ProviderProvedNotApplied,
    ProviderSourceGone,
)
from evergarden.automations.fence import FenceConfig, LeaseToken, SideEffectFence
from evergarden.config import Settings

HUMAN = Actor("admin", "approval-ui", "approval-ui", True)
AGENT = Actor("agent", "codex", "mcp", False)
FENCE = SideEffectFence(FenceConfig("host-a", "host-a", 2, True, True))
LEASE = LeaseToken("test", "slot", "host-a", 2, "nonce")
ALL_KINDS = frozenset(IntentKind)
TRASH_ONLY = frozenset({IntentKind.TRASH})
GMAIL = next(a for a in TEST_ACCOUNTS if a.alias == "gmail")
PRODUCTION = {
    "host_id": "host-a",
    "side_effects_enabled": True,
    "trash_actions_enabled": True,
    "approval_dispatch_enabled": True,
}


class Clock:
    def __init__(self, now: dt.datetime):
        self.now = now

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **delta) -> None:
        self.now += dt.timedelta(**delta)


def payload_for(kind: IntentKind, stable_id: str) -> dict:
    if kind is IntentKind.SEND:
        return {
            "account": "gmail",
            "from": GMAIL.address,
            "to": ["friend@example.test"],
            "subject": "Hello",
            "body": "Body",
            "message_id": f"<{stable_id}@example.test>",
            "date": "Mon, 17 Aug 2026 12:00:00 +0000",
        }
    payload = {
        "account": "gmail",
        "stable_message_id": stable_id,
        "source_folder": "INBOX",
        "source_uid": 7,
        "source_uid_validity": "777",
        "provider_message_id": "source@example.test",
        "raw_body_sha256": "b" * 64,
    }
    if kind is IntentKind.MARK:
        return {**payload, "action": "seen"}
    destination = {
        IntentKind.TRASH: GMAIL.trash_folder,
        IntentKind.ARCHIVE: GMAIL.archive_folder,
        IntentKind.MOVE: "Notes",
    }[kind]
    return {
        **payload,
        "operation": kind.value,
        "destination": destination,
        "copy_preserve_source_fallback": False,
    }


def prepare(service, *, kind=IntentKind.TRASH, lifetime=dt.timedelta(hours=1), stable_id=None):
    return service.prepare(
        kind=kind,
        payload=payload_for(kind, stable_id or uuid.uuid4().hex[:24]),
        actor=AGENT,
        lifetime=lifetime,
    )


def approve(service, draft, *, actor=HUMAN, **kwargs):
    return service.approve(
        draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=actor, **kwargs
    )


def executor(service, provider, *, fence=FENCE):
    return lambda **kwargs: service.execute(**kwargs, fence=fence, lease=LEASE, executor=provider)


def make_dispatcher(service, provider, *, kinds=ALL_KINDS):
    return ApprovalDispatcher(service, executor(service, provider), kinds=kinds, host="host-a")


def call_once(service, draft, approval, provider):
    return executor(service, provider)(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=draft.payload,
        expected_kind=draft.kind,
    )


def raising(error):
    def provider(*_):
        raise error

    return provider


def succeeding(calls):
    def provider(*_):
        calls.append(1)
        return {}

    return provider


def execution(service, approval):
    return service.repository.get_execution_for_approval(approval.approval_id)


@pytest.mark.parametrize(
    "kind,batch",
    [
        (IntentKind.TRASH, False),
        (IntentKind.TRASH, True),
        (IntentKind.SEND, False),
        (IntentKind.ARCHIVE, False),
        (IntentKind.MOVE, False),
        (IntentKind.MARK, False),
    ],
)
def test_human_approval_is_durable_and_survives_draft_expiry(fixed_now, kind, batch):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, kind=kind, lifetime=dt.timedelta(seconds=1))
    if batch:
        approval = service.approve_batch(items=[(draft.draft_id, draft.payload_hash)], actor=HUMAN)[
            0
        ]["approval"]
    else:
        approval = approve(service, draft)
    assert approval.approval_source is ApprovalSource.HUMAN
    # A human approval is a durable work order; it never expires.
    assert approval.expires_at is None
    clock.advance(days=7)
    calls = []
    assert make_dispatcher(service, succeeding(calls)).run_once() == {"confirmed": 1}
    assert calls == [1]
    assert service.review(draft.draft_id)["status"] == "confirmed"


def test_human_approvals_of_every_kind_run_and_policy_approvals_never_do(fixed_now):
    clock = Clock(fixed_now)
    repository = ApprovalRepository()
    service = ApprovalService(repository, now=clock)
    policy = ApprovalService(
        repository, now=clock, auto_approve_kinds=frozenset({IntentKind.ARCHIVE, IntentKind.MARK})
    )
    human = {kind: approve(service, prepare(service, kind=kind)) for kind in IntentKind}
    short = prepare(policy, kind=IntentKind.ARCHIVE, lifetime=dt.timedelta(minutes=10))
    policy_drafts = [short, prepare(policy, kind=IntentKind.MARK)]
    policy_approvals = [service.approval_for(draft.draft_id) for draft in policy_drafts]
    assert {a.approval_source for a in policy_approvals} == {ApprovalSource.POLICY}
    # A policy approval never outlives its draft; only humans get a full window.
    assert policy_approvals[0].expires_at == short.expires_at
    calls = []
    dispatcher = make_dispatcher(service, succeeding(calls))

    assert dispatcher.run_once() == {"confirmed": 5}
    assert len(calls) == 5
    assert {kind: execution(service, a).state for kind, a in human.items()} == {
        kind: ExecutionState.CONFIRMED for kind in IntentKind
    }
    assert dispatcher.run_once() == {}
    assert all(execution(service, a) is None for a in policy_approvals)
    page = {item["draft_id"]: item for item in service.execution_page(limit=20, offset=0)["drafts"]}
    assert [page[d.draft_id]["status"] for d in policy_drafts] == ["awaiting_client"] * 2
    assert [page[d.draft_id]["approval"]["source"] for d in policy_drafts] == ["policy"] * 2

    clock.advance(hours=1)
    assert dispatcher.run_once() == {}
    lapsed = service.execution_page(limit=20, offset=0, status="failed")["drafts"]
    # Unexecuted policy approvals stay visible as failures, and cannot be revoked.
    assert {(i["draft_id"], i["status"], i["phase"], i["revocable"]) for i in lapsed} == {
        (draft.draft_id, "client_expired", "failed", False) for draft in policy_drafts
    }
    assert len(calls) == 5


def legacy_expired_approval(service, draft, *, expired_at):
    """A pre-durable-model human approval whose expiry already passed."""
    approval = Approval(
        approval_id=str(uuid.uuid4()),
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        approved_by=HUMAN.subject,
        approved_client=HUMAN.client_id,
        approved_at=expired_at - dt.timedelta(hours=24),
        expires_at=expired_at,
        approval_source=ApprovalSource.HUMAN,
    )
    service.repository.add_approval(approval)
    return approval


def test_only_unclaimed_unrevoked_human_approvals_of_enabled_kinds_run_after_restart(fixed_now):
    repository = ApprovalRepository()
    service = ApprovalService(repository, now=lambda: fixed_now)
    approve(service, prepare(service))
    prepare(service)  # Unapproved is never eligible.
    legacy_expired_approval(
        service, prepare(service), expired_at=fixed_now - dt.timedelta(seconds=1)
    )
    approve(service, prepare(service, kind=IntentKind.ARCHIVE))  # Kind not enabled here.
    calls = []
    # A fresh service/dispatcher, as after a restart, recovers the committed work.
    restored = ApprovalService(repository, now=lambda: fixed_now)
    assert make_dispatcher(restored, succeeding(calls), kinds=TRASH_ONLY).run_once() == {
        "confirmed": 1
    }
    assert make_dispatcher(restored, succeeding(calls), kinds=TRASH_ONLY).run_once() == {}
    assert calls == [1]
    page = restored.execution_page(limit=10, offset=0)
    assert sorted((d["status"], d["phase"]) for d in page["drafts"]) == [
        ("approval_expired", "failed"),
        ("approved", "running"),
        ("confirmed", "confirmed"),
        ("pending_approval", "pending"),
    ]


@pytest.mark.parametrize(
    "failure,state",
    [
        (ProviderDefinitelyRejected("auth failed"), "failed"),
        (ProviderOutcomeUnknown("connection lost"), "unknown"),
    ],
)
def test_failure_is_visible_isolated_and_never_replayed(failure, state):
    service = ApprovalService(ApprovalRepository())
    drafts = [prepare(service), prepare(service)]
    for draft in drafts:
        approve(service, draft)
    calls = []

    def provider(*_):
        calls.append(1)
        if len(calls) == 1:
            raise failure
        return {}

    assert make_dispatcher(service, provider).run_once() == {state: 1, "confirmed": 1}
    assert make_dispatcher(service, provider).run_once() == {}
    page = service.execution_page(limit=10, offset=0)
    assert {d["status"] for d in page["drafts"]} == {state, "confirmed"}
    assert (
        next(d for d in page["drafts"] if d["status"] == state)["error_class"]
        == type(failure).__name__
    )
    assert len(calls) == 2


def test_crash_after_claim_does_not_replay_attempting_action():
    service = ApprovalService(ApprovalRepository())
    draft = prepare(service)
    approval = approve(service, draft)
    service.repository.claim_execution(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        kind=draft.kind,
        payload_hash=draft.payload_hash,
        now=service.now(),
    )
    dispatcher = ApprovalDispatcher(
        service, lambda **_: pytest.fail("must not replay"), kinds=ALL_KINDS, host="host-a"
    )
    assert dispatcher.run_once() == {}
    assert dispatcher.reconcile_once() == {}
    assert service.execution_page(limit=10, offset=0)["drafts"][0]["status"] == "attempting"


def test_new_approval_cannot_replay_older_uncertain_operation_on_same_message():
    service = ApprovalService(ApprovalRepository())
    first = prepare(service, stable_id="a" * 24)
    approve(service, first)
    # Pending duplicates collapse into one draft, so the second request for the
    # same message arrives after the first was already approved.
    second = prepare(service, stable_id="a" * 24)
    assert second.draft_id != first.draft_id
    approve(service, second)
    calls = []

    def provider(*_):
        calls.append(1)
        raise ProviderOutcomeUnknown("synthetic timeout")

    assert make_dispatcher(service, provider).run_once() == {"unknown": 1, "blocked": 1}
    assert make_dispatcher(service, provider).run_once() == {"blocked": 1}
    assert calls == [1]
    assert {d["status"] for d in service.execution_page(limit=10, offset=0)["drafts"]} == {
        "unknown",
        "blocked",
    }


def test_blocked_oldest_approval_does_not_starve_other_messages(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    approve(service, prepare(service, stable_id="a" * 24))
    make_dispatcher(service, raising(ProviderOutcomeUnknown("synthetic timeout"))).run_once()
    clock.advance(seconds=1)
    approve(service, prepare(service, stable_id="a" * 24))
    clock.advance(seconds=1)
    approve(service, prepare(service))
    calls = []
    dispatcher = make_dispatcher(service, succeeding(calls))
    assert dispatcher.run_once(limit=1) == {"blocked": 1, "confirmed": 1}
    assert calls == [1]


def test_two_dispatchers_and_client_racing_execute_provider_once():
    service = ApprovalService(ApprovalRepository())
    draft = prepare(service)
    approval = approve(service, draft)
    barrier = threading.Barrier(3)
    calls = []
    execute = executor(service, succeeding(calls))

    def run(index):
        barrier.wait()
        if index == 2:
            return execute(
                approval_id=approval.approval_id,
                draft_id=draft.draft_id,
                current_payload=draft.payload,
                expected_kind=IntentKind.TRASH,
            )
        return ApprovalDispatcher(service, execute, kinds=ALL_KINDS, host="host-a").run_once()

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(run, range(3)))
    assert calls == [1]


def test_provider_not_attempted_keeps_approval_retryable_until_backoff(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service)
    approval = approve(service, draft)
    calls = []

    def provider(*_):
        calls.append(1)
        if len(calls) == 1:
            raise ProviderNotAttempted("IMAP login failed before any mailbox command")
        return {}

    dispatcher = make_dispatcher(service, provider)
    assert dispatcher.run_once() == {"retryable": 1}
    assert dispatcher.last_item_error_class == "ProviderNotAttempted"
    first = execution(service, approval)
    assert (first.state, first.attempt, first.error_class) == (
        ExecutionState.RETRYABLE,
        1,
        "ProviderNotAttempted",
    )
    review = service.review(draft.draft_id)
    assert review["status"] == "retryable"
    assert review["approval"]["approval_id"] == approval.approval_id

    clock.advance(seconds=59)
    assert dispatcher.run_once() == {}
    assert calls == [1]
    clock.advance(seconds=1)
    assert dispatcher.run_once() == {"confirmed": 1}
    retried = execution(service, approval)
    assert (retried.action_id, retried.state, retried.attempt, retried.error_class) == (
        first.action_id,
        ExecutionState.CONFIRMED,
        2,
        None,
    )
    assert calls == [1, 1]


def test_retryable_approval_keeps_retrying_for_days_without_human_action(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service)
    approval = approve(service, draft)
    reachable = [False]
    calls = []

    def provider(*_):
        calls.append(1)
        if not reachable[0]:
            raise ProviderNotAttempted("provider unreachable")
        return {}

    dispatcher = make_dispatcher(service, provider)
    assert dispatcher.run_once() == {"retryable": 1}
    # Durable approvals never lapse: days later the same approval still runs.
    clock.advance(days=3)
    reachable[0] = True
    assert dispatcher.run_once() == {"confirmed": 1}
    assert (execution(service, approval).state, execution(service, approval).attempt) == (
        ExecutionState.CONFIRMED,
        2,
    )
    assert calls == [1, 1]


def test_revoked_approval_is_never_claimed_and_stays_revoked(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    waiting = prepare(service)
    retryable = prepare(service)
    approve(service, waiting)
    retryable_approval = approve(service, retryable)
    # Revoking the never-claimed approval keeps it out of the very next scan.
    first = service.revoke(items=[(waiting.draft_id, waiting.payload_hash)], actor=HUMAN)
    assert [(r["status"], None) for r in first["results"]] == [("revoked", None)]
    assert [row["previous_state"] for row in first["revoked"]] == [None]
    dispatcher = make_dispatcher(service, raising(ProviderNotAttempted("unreachable")))
    assert dispatcher.run_once() == {"retryable": 1}
    clock.advance(minutes=5)

    value = service.revoke(items=[(retryable.draft_id, retryable.payload_hash)], actor=HUMAN)
    assert [r["status"] for r in value["results"]] == ["revoked"]
    assert [row["previous_state"] for row in value["revoked"]] == ["RETRYABLE"]
    calls = []
    assert make_dispatcher(service, succeeding(calls)).run_once() == {}
    assert calls == []
    review = service.review(waiting.draft_id)
    assert (review["status"], review["phase"], review["revocable"]) == ("revoked", "failed", False)
    # A direct execute call cannot resurrect the revoked retryable row either.
    with pytest.raises(ApprovalError, match="APPROVAL_CLOSED_BEFORE_PROVIDER_REACHED"):
        call_once(service, retryable, retryable_approval, succeeding(calls))
    # Revoking again, or revoking non-waiting rows, changes nothing.
    again = service.revoke(items=[(waiting.draft_id, waiting.payload_hash)], actor=HUMAN)
    assert [r["status"] for r in again["results"]] == ["failed"]
    with pytest.raises(ApprovalError, match="human-verified"):
        service.revoke(items=[(waiting.draft_id, waiting.payload_hash)], actor=AGENT)


def test_stale_attempting_rows_of_any_source_are_reconciled_without_replay(fixed_now):
    clock = Clock(fixed_now)
    repository = ApprovalRepository()
    service = ApprovalService(repository, now=clock)
    policy = ApprovalService(
        repository, now=clock, auto_approve_kinds=frozenset({IntentKind.ARCHIVE})
    )
    human_draft = prepare(service)
    client_draft = prepare(policy, kind=IntentKind.ARCHIVE)
    claimed = [
        (human_draft, approve(service, human_draft)),
        (client_draft, service.approval_for(client_draft.draft_id)),
    ]
    for draft, approval in claimed:
        repository.claim_execution(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            kind=draft.kind,
            payload_hash=draft.payload_hash,
            now=clock(),
        )
    reconciled = []
    executed = []

    def reconcile(payload, _key):
        reconciled.append(payload["stable_message_id"])
        return {"status": "moved", "verified": True}

    provider = SimpleNamespace(execute=succeeding(executed), reconcile=reconcile)
    dispatcher = make_dispatcher(service, provider)
    clock.advance(minutes=4, seconds=59)
    assert dispatcher.reconcile_once() == {}
    assert dispatcher.run_once() == {}
    clock.advance(seconds=1)
    assert dispatcher.reconcile_once() == {"reconciled": 2}
    assert {execution(service, approval).state for _, approval in claimed} == {
        ExecutionState.CONFIRMED
    }
    assert sorted(reconciled) == sorted(d.payload["stable_message_id"] for d, _ in claimed)
    assert executed == []


def test_mark_prepare_rejects_unknown_account_before_burning_an_approval(fixed_now):
    service = ApprovalService(ApprovalRepository(), now=Clock(fixed_now))
    payload = {**payload_for(IntentKind.MARK, "f" * 24), "account": "nonexistent"}
    with pytest.raises(ApprovalError, match="account"):
        service.prepare(kind=IntentKind.MARK, payload=payload, actor=AGENT)


def test_unknown_row_of_a_disabled_kind_is_still_reconciled(fixed_now):
    # Reconciliation is read-only, so it must cover kinds this host no longer
    # dispatches: an UNKNOWN trash row created while trash was enabled would
    # otherwise never resolve and block its message forever.
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, kind=IntentKind.TRASH, stable_id="d" * 24)
    approval = approve(service, draft)

    def execute(*_):
        raise ProviderOutcomeUnknown("connection lost after MOVE")

    enabled = make_dispatcher(service, SimpleNamespace(execute=execute, reconcile=lambda *_: None))
    assert enabled.run_once() == {"unknown": 1}

    # Trash is now disabled on this host; the dispatcher no longer executes it.
    disabled = make_dispatcher(
        service,
        SimpleNamespace(
            execute=lambda *_: {},
            reconcile=lambda *_: {"status": "missing", "verified": True},
        ),
        kinds=ALL_KINDS - {IntentKind.TRASH},
    )
    clock.advance(minutes=10)
    assert disabled.reconcile_once() == {"reconciled": 1}
    assert execution(service, approval).state is ExecutionState.CONFIRMED


def test_disabled_kind_is_never_replayed_even_when_proven_not_applied(fixed_now):
    # Reconciliation stays read-only for kinds this host does not dispatch:
    # proof of absence ends the row FAILED instead of re-issuing the trash.
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, kind=IntentKind.TRASH, stable_id="e" * 24)
    approval = approve(service, draft)
    executed = []

    def execute(*_):
        executed.append(1)
        raise ProviderOutcomeUnknown("connection lost after MOVE")

    enabled = make_dispatcher(service, SimpleNamespace(execute=execute, reconcile=lambda *_: None))
    assert enabled.run_once() == {"unknown": 1}
    disabled = make_dispatcher(
        service,
        SimpleNamespace(
            execute=lambda *_: pytest.fail("a disabled kind must not be replayed"),
            reconcile=raising(ProviderProvedNotApplied("source unchanged, destination empty")),
        ),
        kinds=ALL_KINDS - {IntentKind.TRASH},
    )
    clock.advance(minutes=10)
    assert disabled.reconcile_once() == {"reconciled_failed": 1}
    row = execution(service, approval)
    assert (row.state, row.error_class) == (
        ExecutionState.FAILED,
        "ProviderProvedNotApplied",
    )
    assert executed == [1]


def test_fenced_off_trash_is_reconciled_but_never_replayed(fixed_now):
    # EVERGARDEN_TRASH_ACTIONS_ENABLED=false must not freeze an UNKNOWN trash
    # row: resuming it is read-only and allowed, replaying it is not.
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, kind=IntentKind.TRASH, stable_id="f" * 24)
    approval = approve(service, draft)

    def execute(*_):
        raise ProviderOutcomeUnknown("connection lost after MOVE")

    assert make_dispatcher(
        service, SimpleNamespace(execute=execute, reconcile=lambda *_: None)
    ).run_once() == {"unknown": 1}

    trash_fenced = SideEffectFence(FenceConfig("host-a", "host-a", 2, True, False))
    provider = SimpleNamespace(
        execute=lambda *_: pytest.fail("fenced-off trash must not be replayed"),
        reconcile=lambda *_: None,
    )
    runner = lambda **kwargs: service.execute(  # noqa: E731
        **kwargs, fence=trash_fenced, lease=LEASE, executor=provider
    )
    clock.advance(minutes=10)
    # Read-only resume proceeds despite the fence; the inconclusive replay is
    # suppressed by it, so the row backs off instead of mutating the mailbox.
    with pytest.raises(ApprovalError, match="remains unknown"):
        runner(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=draft.payload,
            expected_kind=draft.kind,
        )
    assert execution(service, approval).state is ExecutionState.UNKNOWN


@pytest.mark.parametrize("inconclusive", [None, OSError("ambiguous copies")])
def test_inconclusive_unknown_backs_off_then_ends_unverified_and_unblocks(fixed_now, inconclusive):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, stable_id="same-message")
    approval = approve(service, draft)
    executed = []
    reconciled = []
    settled = []

    def execute(*_):
        # Every attempt — including idempotent replays — stays unprovable, so
        # the row keeps backing off and finally ends as OutcomeUnverified.
        executed.append(1)
        if settled:
            return {}
        raise ProviderOutcomeUnknown("connection lost after MOVE")

    def reconcile(*_):
        reconciled.append(clock())
        if inconclusive is not None:
            raise inconclusive

    dispatcher = make_dispatcher(service, SimpleNamespace(execute=execute, reconcile=reconcile))
    assert dispatcher.run_once() == {"unknown": 1}
    later = approve(service, prepare(service, stable_id="same-message"))
    assert dispatcher.run_once() == {"blocked": 1}
    clock.advance(minutes=10)
    assert dispatcher.reconcile_once() == {"reconcile_inconclusive": 1}
    row = execution(service, approval)
    assert (row.state, row.error_class, row.updated_at) == (
        ExecutionState.UNKNOWN,
        "ProviderOutcomeUnknown",
        clock(),
    )
    clock.advance(minutes=10, seconds=-1)
    assert dispatcher.reconcile_once() == {}
    clock.advance(seconds=1)
    assert dispatcher.reconcile_once() == {"reconcile_inconclusive": 1}
    assert service.review(draft.draft_id)["phase"] == "running"

    clock.advance(hours=24)
    assert dispatcher.reconcile_once() == {"reconciled_failed": 1}
    row = execution(service, approval)
    assert (row.state, row.error_class) == (ExecutionState.FAILED, "OutcomeUnverified")
    review = service.review(draft.draft_id)
    # The unverified outcome is final: it can neither run again nor be revoked.
    assert (review["phase"], review["revocable"]) == ("failed", False)
    assert (
        service.revoke(items=[(draft.draft_id, draft.payload_hash)], actor=HUMAN)["revoked"] == []
    )
    # The ended outcome no longer blocks the newer approval for the same message.
    settled.append(True)
    assert dispatcher.run_once() == {"confirmed": 1}
    assert execution(service, later).state is ExecutionState.CONFIRMED
    # The clean inconclusive reconciles each replayed the idempotent trash.
    assert len(executed) == (5 if inconclusive is None else 2)
    assert len(reconciled) == 3


def test_give_up_age_counts_from_the_latest_attempt_not_the_first(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service)
    approval = approve(service, draft)
    attempts = []

    def execute(*_):
        attempts.append(clock())
        if len(attempts) == 1:
            raise ProviderNotAttempted("provider unreachable")
        raise ProviderOutcomeUnknown("connection lost after MOVE")

    dispatcher = make_dispatcher(
        service, SimpleNamespace(execute=execute, reconcile=lambda *_: None)
    )
    assert dispatcher.run_once() == {"retryable": 1}
    # The durable approval retries by itself long after the first attempt.
    clock.advance(hours=30)
    assert dispatcher.run_once() == {"unknown": 1}
    row = execution(service, approval)
    assert row.created_at == fixed_now
    assert row.last_attempt_at == clock()

    # The first attempt is 30 hours old, but the unknown one is only minutes old.
    clock.advance(minutes=10)
    assert dispatcher.reconcile_once() == {"reconcile_inconclusive": 1}
    assert execution(service, approval).state is ExecutionState.UNKNOWN
    clock.advance(hours=24)
    assert dispatcher.reconcile_once() == {"reconciled_failed": 1}
    row = execution(service, approval)
    assert (row.state, row.error_class) == (ExecutionState.FAILED, "OutcomeUnverified")
    # Two dispatched attempts plus one idempotent replay per reconcile pass.
    assert len(attempts) == 4


def test_unreachable_provider_keeps_unknown_running_past_the_give_up_age(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service)
    approval = approve(service, draft)
    provider = SimpleNamespace(
        execute=raising(ProviderOutcomeUnknown("connection lost after MOVE")),
        reconcile=raising(ProviderNotAttempted("login failed")),
    )
    dispatcher = make_dispatcher(service, provider)
    assert dispatcher.run_once() == {"unknown": 1}
    clock.advance(days=2)
    assert dispatcher.reconcile_once() == {"reconcile_inconclusive": 1}
    assert execution(service, approval).state is ExecutionState.UNKNOWN
    assert service.review(draft.draft_id)["phase"] == "running"


@pytest.mark.parametrize(
    ("kind", "proof"),
    [
        # A vanished message can never be applied: final for every kind.
        (IntentKind.TRASH, ProviderSourceGone("source and destination lack the message")),
        # SEND is never replayed; a proven-absent send ends final.
        (IntentKind.SEND, ProviderProvedNotApplied("no sent copy and no recipient delivery")),
    ],
)
def test_reconciliation_proof_ends_non_replayable_unknown_as_failed(fixed_now, kind, proof):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, kind=kind)
    approval = approve(service, draft)
    executed = []

    def execute(*_):
        executed.append(1)
        raise ProviderOutcomeUnknown("connection lost mid-operation")

    dispatcher = make_dispatcher(
        service, SimpleNamespace(execute=execute, reconcile=raising(proof))
    )
    assert dispatcher.run_once() == {"unknown": 1}
    clock.advance(minutes=10)
    assert dispatcher.reconcile_once() == {"reconciled_failed": 1}
    row = execution(service, approval)
    assert (row.state, row.error_class) == (ExecutionState.FAILED, type(proof).__name__)
    review = service.review(draft.draft_id)
    # FAILED is final: recovery means preparing a fresh draft, never a replay.
    assert (review["phase"], review["revocable"]) == ("failed", False)
    assert executed == [1]


@pytest.mark.parametrize("kind", [IntentKind.TRASH, IntentKind.MOVE, IntentKind.MARK])
@pytest.mark.parametrize("outcome", ["proved_not_applied", "inconclusive"])
def test_idempotent_operation_is_replayed_until_the_outcome_is_settled(fixed_now, kind, outcome):
    # move/trash/mark are UID-targeted and converge when re-issued, so an
    # unprovable outcome is retried instead of freezing in UNKNOWN forever.
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, kind=kind)
    approval = approve(service, draft)
    executed = []

    def execute(*_):
        executed.append(1)
        if len(executed) == 1:
            raise ProviderOutcomeUnknown("connection lost mid-operation")
        return {"status": "confirmed", "verified": True}

    def reconcile(*_):
        if outcome == "proved_not_applied":
            raise ProviderProvedNotApplied("source unchanged, destination empty")
        return None

    dispatcher = make_dispatcher(service, SimpleNamespace(execute=execute, reconcile=reconcile))
    assert dispatcher.run_once() == {"unknown": 1}
    clock.advance(minutes=10)
    assert dispatcher.reconcile_once() == {"reconciled": 1}
    row = execution(service, approval)
    assert row.state is ExecutionState.CONFIRMED
    assert executed == [1, 1]


def test_copy_first_strategies_are_never_replayed(fixed_now):
    # A UIDPLUS or copy-preserve move can leave an unverified destination
    # copy; replaying would duplicate it, so the strict handling remains.
    clock = Clock(fixed_now)
    service = ApprovalService(
        ApprovalRepository(), now=clock, uidplus_move_accounts=frozenset({"gmail"})
    )
    payload = {
        **payload_for(IntentKind.MOVE, "a" * 24),
        "uidplus_move_fallback": True,
    }
    draft = service.prepare(kind=IntentKind.MOVE, payload=payload, actor=AGENT)
    approval = approve(service, draft)
    executed = []

    def execute(*_):
        executed.append(1)
        raise ProviderOutcomeUnknown("connection lost after COPY")

    dispatcher = make_dispatcher(
        service, SimpleNamespace(execute=execute, reconcile=lambda *_: None)
    )
    assert dispatcher.run_once() == {"unknown": 1}
    clock.advance(minutes=10)
    assert dispatcher.reconcile_once() == {"reconcile_inconclusive": 1}
    assert execution(service, approval).state is ExecutionState.UNKNOWN
    assert executed == [1]


def test_partial_outcome_is_not_reconciled_and_ends_unverified_after_a_day(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    approval = approve(service, prepare(service))
    provider = SimpleNamespace(
        execute=raising(ProviderPartialOutcome("source deletion flag was rejected")),
        reconcile=lambda *_: pytest.fail("a partial outcome is never reconciled"),
    )
    dispatcher = make_dispatcher(service, provider)
    assert dispatcher.run_once() == {"unknown": 1}
    clock.advance(hours=23, minutes=59)
    assert dispatcher.reconcile_once() == {}
    clock.advance(minutes=1)
    assert dispatcher.reconcile_once() == {"reconciled_failed": 1}
    row = execution(service, approval)
    assert (row.state, row.error_class) == (ExecutionState.FAILED, "OutcomeUnverified")


async def test_stopping_ends_scan_between_items_and_writes_heartbeat(fixed_now, monkeypatch):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    for _ in range(3):
        approve(service, prepare(service))
    monkeypatch.setattr(dispatcher_module, "IDLE_POLL_SECONDS", 0.0)
    calls = []

    def provider(*_):
        calls.append(1)
        dispatcher.stopping.set()
        return {}

    dispatcher = make_dispatcher(service, provider)
    await asyncio.wait_for(dispatcher.run(asyncio.Event()), timeout=5)
    assert calls == [1]
    assert len(service.repository.ready_human_approvals(clock(), kinds=ALL_KINDS, limit=10)) == 2
    status = service.repository.dispatcher_status()
    assert {key: status[key] for key in status if key != "updated_at"} == {
        "host": "host-a",
        "kinds": ["archive", "mark", "move", "send", "trash"],
        "last_scan_at": fixed_now,
        "last_error_class": None,
        "last_item_error_class": None,
        "last_result": {"confirmed": 1},
    }


def test_fence_rejection_is_deferred_and_keeps_the_approval_ready(fixed_now):
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    draft = prepare(service)
    approval = approve(service, draft)
    fences = [SideEffectFence(FenceConfig("host-a", "host-b", 2, True, True))]
    calls = []
    provider = succeeding(calls)

    def execute(**kwargs):
        return service.execute(**kwargs, fence=fences[0], lease=LEASE, executor=provider)

    dispatcher = ApprovalDispatcher(service, execute, kinds=ALL_KINDS, host="host-a")
    assert dispatcher.run_once() == {"deferred": 1}
    assert dispatcher.last_item_error_class == "FenceRejected"
    assert execution(service, approval) is None
    assert service.review(draft.draft_id)["status"] == "approved"
    assert service.repository.ready_human_approvals(fixed_now, kinds=ALL_KINDS, limit=10) == [
        (approval.approval_id, draft.draft_id)
    ]
    fences[0] = FENCE
    assert dispatcher.run_once() == {"confirmed": 1}
    # An item error stays visible after a later successful scan.
    assert dispatcher.last_item_error_class == "FenceRejected"
    assert calls == [1]


async def test_poll_loop_recovers_database_outage_without_reapproval(monkeypatch):
    service = ApprovalService(ApprovalRepository())
    approve(service, prepare(service))
    repository = service.repository
    original_ready = repository.ready_human_approvals
    original_record = repository.record_dispatcher_status
    attempts = []
    heartbeats = []
    stop = asyncio.Event()

    def ready(*args, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("database down")
        return original_ready(*args, **kwargs)

    def record(**kwargs):
        heartbeats.append(kwargs["last_error_class"])
        original_record(**kwargs)

    monkeypatch.setattr(repository, "ready_human_approvals", ready)
    monkeypatch.setattr(repository, "record_dispatcher_status", record)
    monkeypatch.setattr(dispatcher_module, "IDLE_POLL_SECONDS", 0.0)
    calls = []

    def provider(*_):
        calls.append(1)
        stop.set()
        return {}

    dispatcher = make_dispatcher(service, provider)
    await asyncio.wait_for(dispatcher.run(stop), timeout=5)
    assert len(attempts) >= 2 and calls == [1]
    # The outage is recorded, then every later beat (per item and per scan) clears it.
    assert heartbeats[0] == "ConnectionError" and set(heartbeats[1:]) == {None}
    assert dispatcher.last_error_class is None
    assert repository.dispatcher_status()["last_result"] == {"confirmed": 1}


async def test_heartbeat_failure_is_logged_and_never_stops_dispatch(monkeypatch, caplog):
    service = ApprovalService(ApprovalRepository())
    approve(service, prepare(service))
    stop = asyncio.Event()

    def unavailable(**_):
        raise ConnectionError("database down")

    def provider(*_):
        stop.set()
        return {}

    monkeypatch.setattr(service.repository, "record_dispatcher_status", unavailable)
    monkeypatch.setattr(dispatcher_module, "IDLE_POLL_SECONDS", 0.0)
    dispatcher = make_dispatcher(service, provider)
    with caplog.at_level(logging.ERROR, logger=dispatcher_module.LOGGER.name):
        await asyncio.wait_for(dispatcher.run(stop), timeout=5)
    assert dispatcher.last_result == {"confirmed": 1}
    assert "heartbeat_failed error_class=ConnectionError" in caplog.text
    assert "database down" not in caplog.text


def test_mcp_lifespan_starts_and_stops_independent_dispatcher():
    service = ApprovalService(ApprovalRepository())
    approve(service, prepare(service))
    executed = threading.Event()

    def provider(*_):
        executed.set()
        return {}

    runtime = SimpleNamespace(
        approvals=service,
        execute_approved=executor(service, provider),
        approval_session=contextlib.nullcontext,
    )
    with TestClient(
        create_app(Settings(**PRODUCTION), verifier=object(), runtime=runtime)
    ) as client:
        assert executed.wait(timeout=3)
        health = client.get("/healthz").json()["approval_dispatch"]
        assert health["enabled"] and health["running"]
        assert health["kinds"] == ["archive", "mark", "move", "send", "trash"]
        assert (
            service.repository.ready_human_approvals(service.now(), kinds=ALL_KINDS, limit=10) == []
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"approval_dispatch_enabled": False},
        {"side_effects_enabled": False},
        {"active_writer": "host-b", "side_effects_enabled": False},
        {"active_writer": "none", "side_effects_enabled": False},
    ],
)
def test_dispatcher_respects_all_production_fences(overrides):
    service = ApprovalService(ApprovalRepository())
    approve(service, prepare(service))
    runtime = SimpleNamespace(approvals=service, execute_approved=lambda **_: pytest.fail("fenced"))
    settings = Settings(**{**PRODUCTION, **overrides})
    with TestClient(create_app(settings, verifier=object(), runtime=runtime)) as client:
        health = client.get("/healthz").json()["approval_dispatch"]
        assert not health["enabled"] and not health["running"] and health["kinds"] == []
    assert (
        len(service.repository.ready_human_approvals(service.now(), kinds=ALL_KINDS, limit=10)) == 1
    )


def test_disabled_trash_actions_keep_trash_approvals_out_of_dispatch():
    service = ApprovalService(ApprovalRepository())
    draft = prepare(service)
    approve(service, draft)
    calls = []

    def execute_approved(**kwargs):
        calls.append(kwargs)
        return {"state": "CONFIRMED"}

    runtime = SimpleNamespace(
        approvals=service,
        execute_approved=execute_approved,
        approval_session=contextlib.nullcontext,
    )
    settings = Settings(**{**PRODUCTION, "trash_actions_enabled": False})
    with TestClient(create_app(settings, verifier=object(), runtime=runtime)) as client:
        deadline = time.monotonic() + 3
        while client.get("/healthz").json()["approval_dispatch"]["last_scan_at"] is None:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        health = client.get("/healthz").json()["approval_dispatch"]
        assert health["enabled"] and health["kinds"] == ["archive", "mark", "move", "send"]
    assert calls == []
    assert service.review(draft.draft_id)["status"] == "approved"


def test_batch_retry_reports_already_approved_without_a_second_approval():
    service = ApprovalService(ApprovalRepository())
    first, second = prepare(service), prepare(service)
    original = service.approve_batch(items=[(first.draft_id, first.payload_hash)], actor=HUMAN)
    retry = service.approve_batch(
        items=[(first.draft_id, first.payload_hash), (second.draft_id, second.payload_hash)],
        actor=HUMAN,
    )
    assert [r["status"] for r in retry] == ["already_approved", "approved"]
    assert retry[0]["approval"].approval_id == original[0]["approval"].approval_id
    assert len(service.repository.approvals) == 2


def test_revoke_validates_each_item_and_touches_only_waiting_human_approvals(fixed_now):
    clock = Clock(fixed_now)
    repository = ApprovalRepository()
    service = ApprovalService(repository, now=clock)
    policy = ApprovalService(
        repository, now=clock, auto_approve_kinds=frozenset({IntentKind.ARCHIVE})
    )
    drafts = {name: prepare(service) for name in ("waiting", "confirmed", "failed", "wrong_hash")}
    drafts["policy"] = prepare(policy, kind=IntentKind.ARCHIVE)
    drafts["unapproved"] = prepare(service)
    approvals = {
        name: approve(service, drafts[name])
        for name in ("waiting", "confirmed", "failed", "wrong_hash")
    }
    call_once(service, drafts["confirmed"], approvals["confirmed"], succeeding([]))
    with pytest.raises(ProviderDefinitelyRejected):
        call_once(
            service,
            drafts["failed"],
            approvals["failed"],
            raising(ProviderDefinitelyRejected("identity mismatch")),
        )
    requested = [
        (drafts[name].draft_id, drafts[name].payload_hash)
        for name in ("waiting", "confirmed", "failed", "policy", "unapproved")
    ]
    requested += [
        (drafts["wrong_hash"].draft_id, "0" * 64),
        ("missing-draft", "0" * 64),
        (drafts["waiting"].draft_id, drafts["waiting"].payload_hash),
    ]
    value = service.revoke(items=requested, actor=HUMAN)
    assert [(r["status"], r["draft_id"]) for r in value["results"] if r["status"] == "revoked"] == [
        ("revoked", drafts["waiting"].draft_id)
    ]
    details = {r["draft_id"]: r.get("detail") for r in value["results"] if r["status"] == "failed"}
    assert details["missing-draft"] is not None
    assert details[drafts["confirmed"].draft_id] is not None
    # Nothing else changed: finished and policy rows keep their state untouched.
    assert execution(service, approvals["confirmed"]).state is ExecutionState.CONFIRMED
    assert execution(service, approvals["failed"]).state is ExecutionState.FAILED
    assert service.approval_for(drafts["policy"].draft_id).revoked_at is None
    assert service.approval_for(drafts["wrong_hash"].draft_id).revoked_at is None


def test_revoke_canonicalises_ids_and_isolates_malformed_items(fixed_now):
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    draft = prepare(service)
    approve(service, draft)
    value = service.revoke(
        items=[
            ("not-a-uuid", "0" * 64),
            (draft.draft_id.upper(), draft.payload_hash),
            (draft.draft_id, draft.payload_hash),
        ],
        actor=HUMAN,
    )
    # A malformed ID fails alone; a re-cased UUID matches its approval; the
    # canonical duplicate of the same draft is reported as such.
    assert [(r["status"], r.get("detail")) for r in value["results"]] == [
        ("failed", "draft not found"),
        ("revoked", None),
        ("failed", "duplicate draft IDs"),
    ]
    assert value["results"][1]["draft_id"] == draft.draft_id.upper()
    assert service.review(draft.draft_id)["status"] == "revoked"


def test_failed_execution_is_final_and_recovery_needs_a_fresh_draft(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, stable_id="c" * 24)
    approval = approve(service, draft)
    with pytest.raises(ProviderDefinitelyRejected):
        call_once(service, draft, approval, raising(ProviderDefinitelyRejected("login refused")))
    calls = []
    # A FAILED row is terminal: it is never dispatched or revoked again.
    assert make_dispatcher(service, succeeding(calls)).run_once() == {}
    page = service.execution_page(limit=10, offset=0, status="failed")["drafts"]
    assert [(item["status"], item["revocable"]) for item in page] == [("failed", False)]
    assert (
        service.revoke(items=[(draft.draft_id, draft.payload_hash)], actor=HUMAN)["revoked"] == []
    )
    with pytest.raises(ApprovalError, match="definitely rejected"):
        call_once(service, draft, approval, succeeding(calls))
    assert calls == []
    # The same message runs again through a fresh draft and a fresh approval.
    retry = prepare(service, stable_id="c" * 24)
    approve(service, retry)
    assert make_dispatcher(service, succeeding(calls)).run_once() == {"confirmed": 1}
    assert calls == [1]


def test_ready_queue_is_ordered_by_approval_time(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    order = []
    drafts = [prepare(service, stable_id=f"{index}" * 24) for index in range(3)]
    for draft in (drafts[1], drafts[2], drafts[0]):
        approve(service, draft)
        clock.advance(seconds=1)
    assert service.review(drafts[1].draft_id)["queue_position"] == 1
    assert service.review(drafts[0].draft_id)["queue_position"] == 3

    def provider(payload, _key):
        order.append(payload["stable_message_id"])
        return {}

    assert make_dispatcher(service, provider).run_once() == {"confirmed": 3}
    assert order == [d.payload["stable_message_id"] for d in (drafts[1], drafts[2], drafts[0])]


def test_busy_scan_refreshes_the_heartbeat_after_every_item(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    for _ in range(3):
        approve(service, prepare(service))
    seen = []

    def slow_provider(*_):
        # Each provider action takes a minute; the heartbeat must keep pace.
        status = service.repository.dispatcher_status()
        seen.append(None if status is None else clock() - status["last_scan_at"])
        clock.advance(minutes=1)
        return {}

    assert make_dispatcher(service, slow_provider).run_once() == {"confirmed": 3}
    assert seen == [None, dt.timedelta(0), dt.timedelta(0)]
    assert service.repository.dispatcher_status()["last_result"] == {"confirmed": 3}


def test_reconcile_sweep_keeps_the_heartbeat_fresh_and_respects_its_time_budget(
    fixed_now, monkeypatch
):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    for _ in range(3):
        approve(service, prepare(service))
    seen = []

    def slow_reconcile(*_):
        # Each mailbox read takes a minute; the heartbeat must keep pace.
        seen.append(clock() - service.repository.dispatcher_status()["last_scan_at"])
        clock.advance(minutes=1)
        raise ProviderSourceGone("message moved elsewhere")

    provider = SimpleNamespace(
        execute=raising(ProviderOutcomeUnknown("connection lost")), reconcile=slow_reconcile
    )
    dispatcher = make_dispatcher(service, provider)
    assert dispatcher.run_once() == {"unknown": 3}
    clock.advance(minutes=10)
    monkeypatch.setattr(dispatcher_module, "RECONCILE_BUDGET_SECONDS", 0.0)
    assert dispatcher.reconcile_once() == {}
    monkeypatch.setattr(dispatcher_module, "RECONCILE_BUDGET_SECONDS", 45.0)
    assert dispatcher.reconcile_once() == {"reconciled_failed": 3}
    assert seen == [dt.timedelta(minutes=10), dt.timedelta(0), dt.timedelta(0)]
    assert service.repository.dispatcher_status()["last_result"] == {
        "unknown": 3,
        "reconciled_failed": 3,
    }


def test_mailboxes_run_in_parallel_up_to_the_cap_with_one_session_each(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    accounts = [a for a in TEST_ACCOUNTS if a.alias in {"gmail", "outlook", "work"}]
    order: dict[str, list[str]] = {}
    for account in accounts:
        for index in range(3):
            payload = {
                **payload_for(IntentKind.TRASH, f"{account.alias}-{index}"),
                "account": account.alias,
                "destination": account.trash_folder,
            }
            draft = service.prepare(kind=IntentKind.TRASH, payload=payload, actor=AGENT)
            approve(service, draft)
            clock.advance(seconds=1)
    lock = threading.Lock()
    active = [0, 0]
    sessions = []

    def provider(payload, _key):
        with lock:
            active[0] += 1
            active[1] = max(active)
            order.setdefault(payload["account"], []).append(payload["stable_message_id"])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return {}

    @contextlib.contextmanager
    def session():
        with lock:
            sessions.append(threading.get_ident())
        yield

    dispatcher = ApprovalDispatcher(
        service,
        executor(service, provider),
        kinds=ALL_KINDS,
        host="host-a",
        session=session,
        parallel=2,
    )
    assert dispatcher.run_once(limit=2) == {"confirmed": 6}
    # Two mailboxes at a time, never more; each mailbox keeps its own FIFO order.
    assert active[1] == 2
    assert len(sessions) == 3
    assert order == {a.alias: [f"{a.alias}-0", f"{a.alias}-1"] for a in accounts}
    assert dispatcher.run_once(limit=2) == {"confirmed": 3}


def test_identity_rejection_during_reconcile_ends_unverified_and_unblocks_at_once(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    draft = prepare(service, stable_id="same-message")
    approval = approve(service, draft)
    reconciled = []

    def execute(*_):
        if reconciled:
            return {}
        raise ProviderOutcomeUnknown("connection lost after MOVE")

    def reconcile(*_):
        reconciled.append(clock())
        raise ProviderDefinitelyRejected("source UIDVALIDITY changed after approval")

    dispatcher = make_dispatcher(service, SimpleNamespace(execute=execute, reconcile=reconcile))
    assert dispatcher.run_once() == {"unknown": 1}
    later = approve(service, prepare(service, stable_id="same-message"))
    clock.advance(minutes=10)
    dispatcher.reconcile_once()
    row = execution(service, approval)
    # No 24 hour polling loop: re-reading can never prove this outcome.
    assert (row.state, row.error_class) == (ExecutionState.FAILED, "OutcomeUnverified")
    assert len(reconciled) == 1
    assert dispatcher.run_once() == {"confirmed": 1}
    assert execution(service, later).state is ExecutionState.CONFIRMED


def test_duplicate_pending_draft_is_reused_and_a_changed_one_replaces_it(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    first = prepare(service, stable_id="a" * 24)
    clock.advance(minutes=1)
    assert prepare(service, stable_id="a" * 24).draft_id == first.draft_id
    # A different request (another destination) for the same message and kind
    # replaces the waiting draft instead of queueing beside it.
    changed = service.prepare(
        kind=IntentKind.MOVE,
        payload=payload_for(IntentKind.MOVE, "a" * 24),
        actor=AGENT,
    )
    other_kind_pending = {d.draft_id for d in service._pending_drafts()}
    assert other_kind_pending == {first.draft_id, changed.draft_id}
    payload = {**payload_for(IntentKind.TRASH, "a" * 24), "source_uid": 8}
    replacement = service.prepare(kind=IntentKind.TRASH, payload=payload, actor=AGENT)
    pending = {d.draft_id for d in service._pending_drafts()}
    assert pending == {changed.draft_id, replacement.draft_id}
    assert service.review(first.draft_id)["status"] == "draft_expired"


def test_confirmed_move_retires_pending_drafts_for_the_same_message(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    trash = prepare(service, stable_id="a" * 24)
    unrelated = prepare(service)
    clock.advance(minutes=5)
    archive = prepare(service, kind=IntentKind.ARCHIVE, stable_id="a" * 24)
    approve(service, archive)
    calls = []
    dispatcher = make_dispatcher(service, succeeding(calls), kinds=frozenset({IntentKind.ARCHIVE}))
    assert dispatcher.run_once() == {"confirmed": 1}
    # The Trash waiting on the archived message can no longer apply.
    assert service.review(trash.draft_id)["status"] == "draft_expired"
    assert service.review(unrelated.draft_id)["status"] == "pending_approval"


def test_sweep_retires_stale_and_duplicate_pending_drafts(fixed_now):
    clock = Clock(fixed_now)
    service = ApprovalService(ApprovalRepository(), now=clock)
    # Legacy state from before deduplication: two pending Trash for one message.
    stale = prepare(service, stable_id="a" * 24)
    for draft in (prepare(service, stable_id="b" * 24),):
        service.repository.add_draft(
            dataclasses.replace(draft, draft_id=str(uuid.uuid4()), created_at=clock())
        )
    clock.advance(minutes=1)
    archive = prepare(service, kind=IntentKind.ARCHIVE, stable_id="a" * 24)
    approve(service, archive)
    dispatcher = make_dispatcher(service, succeeding([]), kinds=frozenset({IntentKind.ARCHIVE}))
    dispatcher.run_once()
    # Simulate an archive confirmed before supersession existed: the Trash
    # draft is still pending although its message has moved.
    service.repository.drafts[stale.draft_id] = dataclasses.replace(
        service.repository.drafts[stale.draft_id], expires_at=clock() + dt.timedelta(hours=1)
    )
    expired = service.supersede_stale_drafts()
    assert stale.draft_id in expired
    remaining_b = [
        d
        for d in service._with_payloads(service._pending_drafts())
        if d.payload["stable_message_id"] == "b" * 24
    ]
    assert len(remaining_b) == 1
