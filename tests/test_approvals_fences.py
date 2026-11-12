from __future__ import annotations

import concurrent.futures
import datetime as dt

import pytest

from evergarden.approvals.models import Actor, IntentKind
from evergarden.approvals.service import ApprovalError, ApprovalRepository, ApprovalService
from evergarden.automations.fence import (
    FenceConfig,
    FenceRejected,
    LeaseToken,
    SideEffect,
    SideEffectFence,
)


def _lease(epoch: int = 1, host: str = "host-a") -> LeaseToken:
    return LeaseToken("send-approved", "2026-08-17T08:30:00+01:00", host, epoch, "nonce")


def _send_payload() -> dict:
    return {
        "operation": "send",
        "account": "gmail",
        "from": "sender@example.test",
        "to": ["test@example.test"],
        "cc": [],
        "bcc": [],
        "subject": "Review",
        "body": "Draft",
        "date": "2026-08-17T12:00:00+00:00",
        "message_id": "<action@example.test>",
        "attachments": [],
    }


def _move_payload(destination: str = "Unrelated") -> dict:
    return {
        "operation": "move",
        "account": "gmail",
        "stable_message_id": "a" * 24,
        "source_folder": "INBOX",
        "source_uid": 7,
        "source_uid_validity": "777",
        "provider_message_id": "<source@example.test>",
        "raw_body_sha256": "f" * 64,
        "destination": destination,
        "copy_preserve_source_fallback": False,
    }


def test_read_only_writer_and_permanent_side_effect_fences() -> None:
    read_only = SideEffectFence(FenceConfig("host-a", "host-a", 1, False))
    for effect in SideEffect:
        with pytest.raises(FenceRejected, match="disabled"):
            read_only.assert_allowed(effect, _lease())
        assert read_only.probe(effect)["allowed"] is False
    other_writer = SideEffectFence(FenceConfig("host-a", "host-b", 1, True))
    with pytest.raises(FenceRejected, match="not the active writer"):
        other_writer.assert_allowed(SideEffect.SMTP_SEND, _lease())

    production = SideEffectFence(FenceConfig("host-a", "host-a", 2, True))
    with pytest.raises(FenceRejected, match="required"):
        production.assert_allowed(SideEffect.SMTP_SEND, None)
    with pytest.raises(FenceRejected, match="another host"):
        production.assert_allowed(SideEffect.SMTP_SEND, _lease(epoch=2, host="host-b"))
    with pytest.raises(FenceRejected, match="stale"):
        production.assert_allowed(SideEffect.SMTP_SEND, _lease(epoch=1))
    production.assert_allowed(SideEffect.SMTP_SEND, _lease(epoch=2))
    for name in ("delete", "trash", "expunge"):
        with pytest.raises(FenceRejected, match="permanently"):
            production.assert_allowed(name, _lease(epoch=2))


def test_approval_requires_human_hash_expiry_and_fence_before_consumption(
    fixed_now: dt.datetime,
) -> None:
    repo = ApprovalRepository()
    service = ApprovalService(repo, now=lambda: fixed_now)
    machine = Actor("agent", "codex", "mcp", False)
    human = Actor("eric", "approval-ui", "approval-ui", True)
    payload = _send_payload()
    draft = service.prepare(kind=IntentKind.SEND, payload=payload, actor=machine)
    with pytest.raises(ApprovalError, match="human"):
        service.approve(draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=machine)
    with pytest.raises(ApprovalError, match="changed"):
        service.approve(draft_id=draft.draft_id, payload_hash="wrong", actor=human)
    approval = service.approve(
        draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=human
    )

    read_only = SideEffectFence(FenceConfig("host-a", "host-b", 1, False))
    with pytest.raises(FenceRejected):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=read_only,
            lease=None,
            executor=lambda *_args: {"unexpected": True},
        )
    assert repo.approvals[approval.approval_id].consumed_at is None

    production = SideEffectFence(FenceConfig("host-a", "host-a", 1, True))
    identical_draft = service.prepare(kind=IntentKind.SEND, payload=payload, actor=machine)
    with pytest.raises(ApprovalError, match="different draft"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=identical_draft.draft_id,
            current_payload=payload,
            fence=production,
            lease=_lease(),
            executor=lambda *_args: {},
        )
    provider_calls: list[str] = []

    def execute_provider(_current: dict, key: str) -> dict:
        provider_calls.append(key)
        return {
            "status": "confirmed",
            "operation": "send",
            "provider_object_id": key,
        }

    result = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=production,
        lease=_lease(),
        executor=execute_provider,
    )
    assert result["state"] == "CONFIRMED"
    assert len(result["provider_object_id"]) == 64
    replay = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=production,
        lease=_lease(),
        executor=execute_provider,
    )
    assert replay["replayed"] is True
    assert provider_calls == [result["provider_object_id"]]


def test_approval_one_shot_is_thread_safe(fixed_now: dt.datetime) -> None:
    repo = ApprovalRepository()
    service = ApprovalService(repo, now=lambda: fixed_now)
    machine = Actor("agent", "codex", "mcp", False)
    human = Actor("eric", "approval-ui", "approval-ui", True)
    payload = _move_payload("[Gmail]/All Mail")
    draft = service.prepare(kind=IntentKind.ARCHIVE, payload=payload, actor=machine)
    approval = service.approve(
        draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=human
    )
    fence = SideEffectFence(FenceConfig("host-a", "host-a", 1, True))

    provider_calls: list[str] = []

    def provider(_payload: dict, key: str) -> dict:
        provider_calls.append(key)
        return {
            "status": "confirmed",
            "operation": "archive",
            "provider_object_id": "a" * 24,
        }

    def execute() -> str:
        try:
            service.execute(
                approval_id=approval.approval_id,
                draft_id=draft.draft_id,
                current_payload=payload,
                fence=fence,
                lease=_lease(),
                executor=provider,
            )
            return "ok"
        except ApprovalError:
            return "rejected"

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _index: execute(), range(8)))
    assert outcomes.count("ok") >= 1
    assert len(provider_calls) == 1


def test_approval_payload_hard_denies_delete_destinations(fixed_now: dt.datetime) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    actor = Actor("agent", "codex", "mcp", False)
    for destination in ("Trash", "Deleted Items", "\\Deleted", "EXPUNGE", "Junk", "Bin"):
        with pytest.raises(ApprovalError, match="allowlisted"):
            service.prepare(
                kind=IntentKind.MOVE,
                payload={
                    "account": "outlook",
                    "stable_message_id": "a" * 24,
                    "source_folder": "Inbox",
                    "source_uid": 7,
                    "source_uid_validity": "777",
                    "provider_message_id": "<source@example.test>",
                    "raw_body_sha256": "f" * 64,
                    "destination": destination,
                    "copy_preserve_source_fallback": False,
                },
                actor=actor,
            )


def test_approval_payload_binds_provider_organization_strategy(
    fixed_now: dt.datetime,
) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    actor = Actor("agent", "codex", "mcp", False)
    with pytest.raises(ApprovalError, match="strategy"):
        service.prepare(
            kind=IntentKind.MOVE,
            payload={**_move_payload(), "copy_preserve_source_fallback": True},
            actor=actor,
        )
    with pytest.raises(ApprovalError, match="strategy"):
        service.prepare(
            kind=IntentKind.MOVE,
            payload={
                key: value
                for key, value in _move_payload().items()
                if key != "copy_preserve_source_fallback"
            },
            actor=actor,
        )
    icloud = {
        **_move_payload("Archive"),
        "account": "icloud",
        "copy_preserve_source_fallback": True,
    }
    assert service.prepare(kind=IntentKind.ARCHIVE, payload=icloud, actor=actor).payload == icloud


@pytest.mark.parametrize(
    ("kind", "payload"),
    (
        (IntentKind.SEND, _send_payload()),
        (IntentKind.MOVE, _move_payload()),
    ),
)
def test_smtp_and_move_external_success_local_timeout_never_replay(
    fixed_now: dt.datetime, kind: IntentKind, payload: dict
) -> None:
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    draft = service.prepare(
        kind=kind,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    approval = service.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    class AcceptedThenTimeout:
        def __init__(self):
            self.external_calls: list[str] = []
            self.reconciliations: list[str] = []

        def execute(self, _payload: dict, key: str) -> dict:
            self.external_calls.append(key)
            raise TimeoutError("provider accepted the effect before the local timeout")

        def reconcile(self, _payload: dict, key: str) -> dict:
            self.reconciliations.append(key)
            return {
                "status": "confirmed",
                "operation": "send" if kind is IntentKind.SEND else "move",
                "provider_object_id": "provider-object",
                "reconciled": True,
            }

    executor = AcceptedThenTimeout()

    fence = SideEffectFence(FenceConfig("host-a", "host-a", 1, True))
    with pytest.raises(TimeoutError, match="provider accepted"):
        service.execute(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            current_payload=payload,
            fence=fence,
            lease=_lease(),
            executor=executor,
        )
    recovered = service.execute(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        current_payload=payload,
        fence=fence,
        lease=_lease(),
        executor=executor,
    )
    assert recovered["state"] == "CONFIRMED"
    assert recovered["reconciled"] is True
    assert len(executor.external_calls) == 1
    assert executor.reconciliations == executor.external_calls
