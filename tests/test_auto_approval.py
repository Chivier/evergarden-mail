from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.mcp.main import create_app
from evergarden.approvals.models import Actor, IntentKind
from evergarden.approvals.service import ApprovalError, ApprovalRepository, ApprovalService
from evergarden.archive.sqlite_archive import ArchiveReader
from evergarden.auth.models import InvalidToken, Principal
from evergarden.automations.fence import FenceConfig, LeaseToken, SideEffectFence
from evergarden.config import Settings, parse_auto_approve
from evergarden.mcp.tools import ToolRuntime

RESOURCE = "https://mail.test/mcp"
SEND_ARGUMENTS = {
    "account": "gmail",
    "to": ["recipient@example.test"],
    "subject": "Auto approved",
    "body": "Sent without a human click",
}


def test_parse_auto_approve_expands_all_and_refuses_trash() -> None:
    assert parse_auto_approve("") == frozenset()
    assert parse_auto_approve("  ") == frozenset()
    assert parse_auto_approve("send") == {"send"}
    assert parse_auto_approve("send, Archive ,move,mark") == {"send", "archive", "move", "mark"}
    assert parse_auto_approve("all") == {"send", "archive", "move", "mark"}

    with pytest.raises(ValueError, match="never include trash"):
        parse_auto_approve("send,trash")
    with pytest.raises(ValueError, match="never include trash"):
        parse_auto_approve("trash")
    with pytest.raises(ValueError, match="unknown auto-approve"):
        parse_auto_approve("send,expunge")
    with pytest.raises(ValueError, match="cannot be combined"):
        parse_auto_approve("all,send")


def test_settings_reject_a_trash_auto_approval() -> None:
    settings = Settings(
        mcp_resource=RESOURCE,
        oauth_issuer="https://auth.test",
        auto_approve="all",
    )
    assert settings.auto_approve_kinds == {"send", "archive", "move", "mark"}

    with pytest.raises(ValueError, match="never include trash"):
        Settings(
            mcp_resource=RESOURCE,
            oauth_issuer="https://auth.test",
            auto_approve="send,trash",
        )


def test_approval_service_refuses_to_auto_approve_trash() -> None:
    with pytest.raises(ApprovalError, match="trash can never be auto-approved"):
        ApprovalService(ApprovalRepository(), auto_approve_kinds=frozenset({IntentKind.TRASH}))


def _mark_payload() -> dict:
    return {
        "account": "gmail",
        "stable_message_id": "a" * 24,
        "source_folder": "INBOX",
        "source_uid": "1",
        "source_uid_validity": "777",
        "provider_message_id": "<a@example.test>",
        "action": "seen",
    }


def test_prepare_issues_an_approval_only_for_configured_kinds() -> None:
    approvals = ApprovalService(
        ApprovalRepository(), auto_approve_kinds=frozenset({IntentKind.MARK})
    )
    actor = Actor("user", "client-mcp", "mcp", False)

    marked = approvals.prepare(kind=IntentKind.MARK, payload=_mark_payload(), actor=actor)
    approval = approvals.approval_for(marked.draft_id)
    assert approval is not None
    assert approval.draft_id == marked.draft_id
    assert approval.payload_hash == marked.payload_hash
    assert approval.approved_by == "user"
    assert approval.consumed_at is None
    # The approval never outlives the draft it is bound to.
    assert approval.expires_at <= marked.expires_at
    # A policy approval waits for the client that prepared it.
    assert approvals.review(marked.draft_id)["status"] == "awaiting_client"

    # A kind outside the policy keeps its human gate.
    unconfigured = approvals.prepare(
        kind=IntentKind.SEND,
        payload={
            "account": "gmail",
            "from": "mailbox@gmail.example",
            "to": ["recipient@example.test"],
            "subject": "Still gated",
            "body": "Still gated",
            "message_id": "<gated@example.test>",
            "date": "2026-08-26T08:00:00+00:00",
        },
        actor=actor,
    )
    assert approvals.approval_for(unconfigured.draft_id) is None
    assert approvals.review(unconfigured.draft_id)["status"] == "pending_approval"


class _TokenVerifier:
    async def verify(self, token: str) -> Principal:
        mapping = {
            "draft": ["mail:draft"],
            "send-approved": ["mail:send-approved"],
            "organize": ["mail:organize"],
            "delete": ["mail:delete"],
            "metadata": ["mail:metadata"],
        }
        if token not in mapping:
            raise InvalidToken("invalid")
        return Principal.build(
            subject="user",
            client_id=f"client-{token}",
            scopes=mapping[token],
            audience=RESOURCE,
            issuer="https://auth.test",
        )


def _client(archive_dir: Path, *, auto_approve: str) -> tuple[TestClient, list[dict]]:
    approvals = ApprovalService(
        ApprovalRepository(),
        auto_approve_kinds=parse_auto_approve(auto_approve),
    )
    fence = SideEffectFence(FenceConfig("host-a", "host-a", 1, True))
    lease = LeaseToken("approved-mail-action", "approval", "host-a", 1, "nonce")
    sent: list[dict] = []

    def executor(payload: dict, idempotency_key: str) -> dict:
        sent.append({"payload": payload, "idempotency_key": idempotency_key})
        return {
            "status": "confirmed",
            "operation": "send",
            "message_id": payload["message_id"],
            "sent_copy_verified": True,
        }

    runtime = ToolRuntime(
        archive=ArchiveReader(archive_dir),
        approvals=approvals,
        execute_approved=lambda **kwargs: approvals.execute(
            **kwargs, fence=fence, lease=lease, executor=executor
        ),
        mode="production",
        side_effects_enabled=True,
    )
    settings = Settings(
        mcp_resource=RESOURCE,
        oauth_issuer="https://auth.test",
        archive_dir=archive_dir,
        auto_approve=auto_approve,
    )
    return (
        TestClient(create_app(settings, verifier=_TokenVerifier(), runtime=runtime)),
        sent,
    )


def _tool_value(client: TestClient, token: str, name: str, arguments: dict) -> dict:
    response = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    assert response.status_code == 200
    result = response.json()["result"]
    text = result["content"][0]["text"]
    is_error = bool(result.get("isError"))
    return {"value": text if is_error else json.loads(text), "is_error": is_error}


def test_prepare_send_returns_a_usable_approval_and_sends_exactly_once(
    archive_dir: Path,
) -> None:
    client, sent = _client(archive_dir, auto_approve="all")

    draft = _tool_value(client, "draft", "prepare_send", SEND_ARGUMENTS)["value"]
    assert draft["requires_human_approval"] is False
    assert draft["approval_available_via_mcp"] is True
    assert draft["approval_id"]
    assert draft["approval_expires_at"] <= draft["expires_at"]

    executed = _tool_value(
        client,
        "send-approved",
        "send_approved",
        {
            "approval_id": draft["approval_id"],
            "draft_id": draft["draft_id"],
            "payload": draft["review_packet"],
        },
    )
    assert executed["is_error"] is False
    assert executed["value"]["state"] == "CONFIRMED"
    assert executed["value"]["sent_copy_verified"] is True
    assert len(sent) == 1

    # The one-shot ledger still holds: replaying the approval replays the
    # recorded confirmation instead of handing the message to SMTP twice.
    replay = _tool_value(
        client,
        "send-approved",
        "send_approved",
        {
            "approval_id": draft["approval_id"],
            "draft_id": draft["draft_id"],
            "payload": draft["review_packet"],
        },
    )
    assert replay["value"]["state"] == "CONFIRMED"
    assert replay["value"]["replayed"] is True
    assert len(sent) == 1


def test_a_tampered_payload_is_still_refused_after_auto_approval(archive_dir: Path) -> None:
    client, sent = _client(archive_dir, auto_approve="all")
    draft = _tool_value(client, "draft", "prepare_send", SEND_ARGUMENTS)["value"]

    tampered = _tool_value(
        client,
        "send-approved",
        "send_approved",
        {
            "approval_id": draft["approval_id"],
            "draft_id": draft["draft_id"],
            "payload": {**draft["review_packet"], "to": ["attacker@example.test"]},
        },
    )
    assert tampered["is_error"] is True
    assert sent == []


def test_trash_still_requires_a_human_approval_under_auto_approve_all(archive_dir: Path) -> None:
    client, _ = _client(archive_dir, auto_approve="all")
    preview = _tool_value(
        client,
        "delete",
        "preview_trash",
        {"account": "gmail", "stable_message_id": "a" * 24},
    )["value"]
    assert preview["requires_human_approval"] is True
    assert preview["approval_available_via_mcp"] is False
    assert "approval_id" not in preview


def test_service_info_advertises_the_auto_approval_policy(archive_dir: Path) -> None:
    client, _ = _client(archive_dir, auto_approve="send,mark")
    info = _tool_value(client, "metadata", "service_info", {})["value"]
    assert info["auto_approved_intents"] == ["mark", "send"]
    assert "approve" in info["explicitly_absent"]

    default_client, _ = _client(archive_dir, auto_approve="")
    default_info = _tool_value(default_client, "metadata", "service_info", {})["value"]
    assert default_info["auto_approved_intents"] == []
