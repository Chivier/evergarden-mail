from __future__ import annotations

import dataclasses
import datetime as dt

import pytest

from evergarden.approvals.models import Actor, ExecutionState, IntentKind
from evergarden.approvals.service import (
    ApprovalError,
    ApprovalRepository,
    ApprovalService,
    ProviderDefinitelyRejected,
    ProviderOutcomeUnknown,
    ProviderPartialOutcome,
)
from evergarden.automations.fence import FenceConfig, LeaseToken, SideEffectFence

NOW = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC)
AGENT = Actor("agent", "codex", "mcp", False)
HUMAN = Actor("operator", "approval-ui", "approval-ui", True)


def _send_payload() -> dict:
    return {
        "operation": "send",
        "account": "gmail",
        "from": "mailbox@gmail.example",
        "to": ["recipient@example.test"],
        "cc": [],
        "bcc": [],
        "subject": "Bounded draft",
        "body": "Approved body",
        "date": NOW.isoformat(),
        "message_id": "<draft@evergarden.example.test>",
        "attachments": [],
    }


def _organization_payload(*, operation: str = "archive", destination: str = "[Gmail]/All Mail"):
    return {
        "operation": operation,
        "account": "gmail",
        "stable_message_id": "a" * 24,
        "source_folder": "INBOX",
        "source_uid": 7,
        "source_uid_validity": "777",
        "provider_message_id": "source@example.test",
        "raw_body_sha256": "b" * 64,
        "destination": destination,
        "copy_preserve_source_fallback": False,
    }


def _mark_payload() -> dict:
    value = _organization_payload(operation="mark", destination="")
    value.pop("destination")
    value.pop("copy_preserve_source_fallback")
    value["action"] = "seen"
    return value


def _fence() -> tuple[SideEffectFence, LeaseToken]:
    return (
        SideEffectFence(
            FenceConfig(
                host_id="host-a",
                active_writer="host-a",
                writer_epoch=1,
                side_effects_enabled=True,
                trash_actions_enabled=True,
            )
        ),
        LeaseToken("approved-mail-action", "slot", "host-a", 1, "nonce"),
    )


def _approved(service: ApprovalService, payload: dict | None = None):
    draft = service.prepare(kind=IntentKind.SEND, payload=payload or _send_payload(), actor=AGENT)
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=HUMAN,
    )
    return draft, approval


def test_reference_repository_enforces_one_shot_identity_and_transitions() -> None:
    repository = ApprovalRepository()
    service = ApprovalService(repository, now=lambda: NOW)
    draft, approval = _approved(service)
    with pytest.raises(ApprovalError, match="draft not found"):
        repository.get_draft("missing")
    with pytest.raises(ApprovalError, match="already has"):
        repository.add_approval(
            dataclasses.replace(approval, approval_id="00000000-0000-4000-8000-000000000002")
        )
    with pytest.raises(ApprovalError, match="approval not found"):
        repository.consume("missing", draft.draft_id, draft.payload_hash, NOW)
    with pytest.raises(ApprovalError, match="different draft"):
        repository.consume(approval.approval_id, "other", draft.payload_hash, NOW)
    with pytest.raises(ApprovalError, match="payload hash"):
        repository.consume(approval.approval_id, draft.draft_id, "0" * 64, NOW)

    execution, claimed = repository.claim_execution(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        kind=IntentKind.SEND,
        payload_hash=draft.payload_hash,
        now=NOW,
    )
    assert claimed is True
    replay, claimed = repository.claim_execution(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        kind=IntentKind.SEND,
        payload_hash=draft.payload_hash,
        now=NOW,
    )
    assert claimed is False and replay == execution
    with pytest.raises(ApprovalError, match="identity"):
        repository.claim_execution(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            kind=IntentKind.MARK,
            payload_hash=draft.payload_hash,
            now=NOW,
        )
    with pytest.raises(ApprovalError, match="already consumed"):
        repository.consume(approval.approval_id, draft.draft_id, draft.payload_hash, NOW)
    with pytest.raises(ApprovalError, match="not found"):
        repository.transition_execution(
            "missing",
            expected=frozenset({ExecutionState.ATTEMPTING}),
            state=ExecutionState.UNKNOWN,
            now=NOW,
        )
    with pytest.raises(ApprovalError, match="changed concurrently"):
        repository.transition_execution(
            approval.approval_id,
            expected=frozenset({ExecutionState.CONFIRMED}),
            state=ExecutionState.UNKNOWN,
            now=NOW,
        )


def test_expired_approval_and_human_surface_validation() -> None:
    clock = {"now": NOW}
    repository = ApprovalRepository()
    service = ApprovalService(repository, now=lambda: clock["now"])
    draft = service.prepare(
        kind=IntentKind.SEND,
        payload=_send_payload(),
        actor=AGENT,
        lifetime=dt.timedelta(minutes=30),
    )
    for actor in (
        AGENT,
        Actor("operator", "approval-ui", "mcp", True),
    ):
        with pytest.raises(ApprovalError, match="human-verified"):
            service.approve(draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=actor)
    with pytest.raises(ApprovalError, match="payload changed"):
        service.approve(draft_id=draft.draft_id, payload_hash="0" * 64, actor=HUMAN)
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=HUMAN,
    )
    assert service.review(draft.draft_id)["status"] == "approved"
    # A human approval is durable: it stays executable long past the draft window.
    clock["now"] = NOW + dt.timedelta(days=2)
    assert service.review(draft.draft_id)["status"] == "approved"
    service.revoke(items=[(draft.draft_id, draft.payload_hash)], actor=HUMAN)
    assert service.review(draft.draft_id)["status"] == "revoked"
    with pytest.raises(ApprovalError, match="revoked"):
        repository.consume(
            approval.approval_id,
            draft.draft_id,
            draft.payload_hash,
            clock["now"],
        )

    expiring = service.prepare(
        kind=IntentKind.SEND,
        payload=_send_payload(),
        actor=AGENT,
        lifetime=dt.timedelta(seconds=1),
    )
    clock["now"] += dt.timedelta(seconds=2)
    assert service.review(expiring.draft_id)["status"] == "draft_expired"
    with pytest.raises(ApprovalError, match="draft is expired"):
        service.approve(
            draft_id=expiring.draft_id,
            payload_hash=expiring.payload_hash,
            actor=HUMAN,
        )


@pytest.mark.parametrize(
    ("kind", "payload", "message"),
    [
        (IntentKind.SEND, {}, "send draft requires"),
        (IntentKind.ARCHIVE, {}, "immutable source identity"),
        (
            IntentKind.ARCHIVE,
            {**_organization_payload(), "provider_message_id": "", "raw_body_sha256": ""},
            "provider identity",
        ),
        (
            IntentKind.MOVE,
            _organization_payload(operation="move", destination="Not Allowed"),
            "not allowlisted",
        ),
        (
            IntentKind.MOVE,
            _organization_payload(operation="move", destination="Trash"),
            "not allowlisted",
        ),
        (
            IntentKind.ARCHIVE,
            {**_organization_payload(), "copy_preserve_source_fallback": True},
            "strategy is malformed",
        ),
        (
            IntentKind.TRASH,
            _organization_payload(operation="trash", destination="Wrong Trash"),
            "does not match",
        ),
        (
            IntentKind.TRASH,
            _organization_payload(operation="archive", destination="[Gmail]/Trash"),
            "operation is malformed",
        ),
        (IntentKind.MARK, {}, "immutable source identity"),
        (
            IntentKind.MARK,
            {**_mark_payload(), "provider_message_id": "", "raw_body_sha256": ""},
            "provider identity",
        ),
        (IntentKind.MARK, {**_mark_payload(), "action": "delete"}, "not allowlisted"),
    ],
)
def test_draft_payload_validation_is_fail_closed(
    kind: IntentKind, payload: dict, message: str
) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    with pytest.raises(ApprovalError, match=message):
        service.prepare(kind=kind, payload=payload, actor=AGENT)


class _Executor:
    def __init__(self, *, execute_result=None, execute_error=None, reconcile_result=None):
        self.execute_result = execute_result
        self.execute_error = execute_error
        self.reconcile_result = reconcile_result
        self.execute_calls = 0
        self.reconcile_calls = 0

    def execute(self, _payload: dict, _idempotency_key: str) -> dict:
        self.execute_calls += 1
        if self.execute_error:
            raise self.execute_error
        return self.execute_result

    def reconcile(self, _payload: dict, _idempotency_key: str) -> dict | None:
        self.reconcile_calls += 1
        if isinstance(self.reconcile_result, Exception):
            raise self.reconcile_result
        return self.reconcile_result


def _execute(service: ApprovalService, draft, approval, executor):
    fence, lease = _fence()
    return service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=draft.payload,
        fence=fence,
        lease=lease,
        executor=executor,
        expected_kind=IntentKind.SEND,
    )


def test_unknown_provider_outcome_reconciles_without_replaying_write() -> None:
    repository = ApprovalRepository()
    service = ApprovalService(repository, now=lambda: NOW)
    draft, approval = _approved(service)
    first = _Executor(execute_error=ProviderOutcomeUnknown("timeout"))
    with pytest.raises(ProviderOutcomeUnknown):
        _execute(service, draft, approval, first)
    assert first.execute_calls == 1
    second = _Executor(
        execute_result=None,
        reconcile_result={
            "status": "confirmed",
            "operation": "send",
            "account": "gmail",
            "provider_object_id": "draft@evergarden.example.test",
            "sent_copy_verified": True,
            "sent_copy_state": "verified",
        },
    )
    result = _execute(service, draft, approval, second)
    assert result["state"] == "CONFIRMED"
    assert result["replayed"] is True
    assert second.execute_calls == 0 and second.reconcile_calls == 1
    assert service.review(draft.draft_id)["status"] == "confirmed"


def test_definite_and_partial_provider_failures_are_not_replayed() -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    draft, approval = _approved(service)
    rejected = _Executor(execute_error=ProviderDefinitelyRejected("no"))
    with pytest.raises(ProviderDefinitelyRejected):
        _execute(service, draft, approval, rejected)
    with pytest.raises(ApprovalError, match="definitely rejected"):
        _execute(service, draft, approval, _Executor(execute_result={}))

    partial_service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    partial_draft, partial_approval = _approved(partial_service)
    with pytest.raises(ProviderPartialOutcome):
        _execute(
            partial_service,
            partial_draft,
            partial_approval,
            _Executor(execute_error=ProviderPartialOutcome("some recipients accepted")),
        )
    with pytest.raises(ApprovalError, match="partial outcome; the side effect was not replayed"):
        _execute(
            partial_service,
            partial_draft,
            partial_approval,
            _Executor(execute_result={}),
        )


def test_execution_rejects_payload_endpoint_and_unsafe_provider_results() -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    draft, approval = _approved(service)
    fence, lease = _fence()
    with pytest.raises(ApprovalError, match="endpoint"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=draft.payload,
            fence=fence,
            lease=lease,
            executor=_Executor(execute_result={}),
            expected_kind=IntentKind.MARK,
        )
    with pytest.raises(ApprovalError, match="payload changed"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload={**draft.payload, "subject": "changed"},
            fence=fence,
            lease=lease,
            executor=_Executor(execute_result={}),
        )

    unsafe_service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    unsafe_draft, unsafe_approval = _approved(unsafe_service)
    with pytest.raises(RuntimeError, match="unsafe result fields"):
        _execute(
            unsafe_service,
            unsafe_draft,
            unsafe_approval,
            _Executor(execute_result={"status": "confirmed", "secret": "must-not-escape"}),
        )

    malformed_service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    malformed_draft, malformed_approval = _approved(malformed_service)
    with pytest.raises(RuntimeError, match="malformed result"):
        _execute(
            malformed_service,
            malformed_draft,
            malformed_approval,
            _Executor(execute_result=["not", "a", "dict"]),
        )


def test_confirmation_refresh_is_read_only_and_best_effort() -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    draft, approval = _approved(service)
    initial = _Executor(
        execute_result={
            "status": "confirmed",
            "operation": "send",
            "account": "gmail",
            "provider_object_id": "draft@evergarden.example.test",
            "sent_copy_verified": False,
            "sent_copy_state": "absent",
        }
    )
    assert _execute(service, draft, approval, initial)["replayed"] is False
    refresh = _Executor(
        execute_result=None,
        reconcile_result={
            "status": "confirmed",
            "operation": "send",
            "account": "gmail",
            "provider_object_id": "draft@evergarden.example.test",
            "sent_copy_verified": True,
            "sent_copy_state": "verified",
        },
    )
    result = _execute(service, draft, approval, refresh)
    assert result["sent_copy_verified"] is True
    assert refresh.execute_calls == 0 and refresh.reconcile_calls == 1


def test_default_draft_lifetime_is_six_hours_and_human_approval_never_expires() -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: NOW)
    draft = service.prepare(kind=IntentKind.SEND, payload=_send_payload(), actor=AGENT)
    assert draft.expires_at - draft.created_at == dt.timedelta(hours=6)
    approval = service.approve(
        draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=HUMAN
    )
    assert approval.expires_at is None
