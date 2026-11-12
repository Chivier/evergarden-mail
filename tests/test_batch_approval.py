from __future__ import annotations

import base64
import datetime as dt
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from account_fixtures import TEST_ACCOUNTS
from fastapi.testclient import TestClient

from apps.approval_ui.main import create_app
from evergarden.approvals.models import Actor, IntentKind
from evergarden.approvals.service import (
    ApprovalRepository,
    ApprovalService,
    ProviderDefinitelyRejected,
    ProviderNotAttempted,
    ProviderOutcomeUnknown,
    ProviderSourceGone,
)
from evergarden.auth.admin_session import SESSION_COOKIE, AdminSessionAuth
from evergarden.automations.fence import FenceConfig, LeaseToken, SideEffectFence
from evergarden.config import Settings


def prepare(service, kind=IntentKind.TRASH, lifetime=dt.timedelta(minutes=30), stable_id=None):
    # Each draft is a distinct message unless a test shares one on purpose.
    stable_id = stable_id or uuid.uuid4().hex[:24]
    account = next(item for item in TEST_ACCOUNTS if item.alias == "gmail")
    return service.prepare(
        kind=kind,
        payload={
            "operation": kind.value,
            "account": "gmail",
            "stable_message_id": stable_id,
            "source_folder": "INBOX",
            "source_uid": 7,
            "source_uid_validity": "777",
            "provider_message_id": "source@example.test",
            "raw_body_sha256": "b" * 64,
            "destination": account.trash_folder
            if kind is IntentKind.TRASH
            else account.archive_folder,
            "copy_preserve_source_fallback": False,
        },
        actor=Actor("agent", "codex", "mcp", False),
        lifetime=lifetime,
    )


def client_for(tmp_path, service):
    path = tmp_path / "session-key"
    path.write_text(base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode())
    path.chmod(0o600)
    token, _ = AdminSessionAuth(session_key_file=path).issue("admin")
    client = TestClient(
        create_app(
            Settings(
                approval_ui_enabled=True, admin_session_key_file=path, admin_secure_cookies=False
            ),
            approvals=service,
        )
    )
    return client, token


def item(draft):
    return {"draft_id": draft.draft_id, "payload_hash": draft.payload_hash}


def test_batch_auth_scope_expiry_hash_and_partial_results(tmp_path):
    service = ApprovalService(ApprovalRepository())
    good = prepare(service)
    altered = prepare(service)
    expired = prepare(service, lifetime=dt.timedelta(seconds=-1))
    other = prepare(service, IntentKind.ARCHIVE)
    client, token = client_for(tmp_path, service)
    body = {
        "items": [
            item(good),
            {**item(altered), "payload_hash": "wrong"},
            item(expired),
            item(other),
        ]
    }
    assert client.get("/drafts").status_code == 401
    assert client.post("/approvals/batch", json=body).status_code == 401
    client.cookies.set(SESSION_COOKIE, token)
    assert client.post("/approvals/batch", json=body).status_code == 403
    headers = {"X-CSRF-Token": client.get("/session").json()["csrf"]}
    pending = client.get("/drafts").json()["drafts"]
    assert {v["draft_id"] for v in pending} == {good.draft_id, altered.draft_id}
    assert client.post("/approvals/batch", json={"items": []}, headers=headers).status_code == 422
    assert (
        client.post(
            "/approvals/batch", json={"items": [item(good)] * 201}, headers=headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/approvals/batch", json={"items": [item(good)] * 2}, headers=headers
        ).status_code
        == 400
    )
    assert service.approval_for(good.draft_id) is None
    results = client.post("/approvals/batch", json=body, headers=headers).json()["results"]
    assert [v["status"] for v in results] == ["approved", "failed", "failed", "failed"]
    assert results[0]["approval"]["approved_by"] == "admin"
    assert service.repository.executions == {}
    assert client.post("/approvals", json=item(good), headers=headers).status_code == 409
    assert client.post("/approvals", json=item(expired), headers=headers).status_code == 409
    repeated = client.post("/approvals/batch", json={"items": [item(good)]}, headers=headers).json()
    # A retry of an already approved item reports success, not a failure.
    assert repeated["results"][0]["status"] == "already_approved"
    assert repeated["results"][0]["approval"]["source"] == "human"
    assert len(service.repository.approvals) == 1
    assert [v["draft_id"] for v in client.get("/drafts").json()["drafts"]] == [altered.draft_id]


def test_batch_disabled_and_pagination(tmp_path):
    service = ApprovalService(ApprovalRepository())
    disabled = TestClient(create_app(Settings(), approvals=service))
    draft = prepare(service)
    assert disabled.get("/drafts").status_code == 503
    assert disabled.post("/approvals/batch", json={"items": [item(draft)]}).status_code == 503
    for _ in range(200):
        prepare(service)
    client, token = client_for(tmp_path, service)
    client.cookies.set(SESSION_COOKIE, token)
    first = client.get("/drafts").json()
    second = client.get("/drafts?offset=200").json()
    assert len(first["drafts"]) == 200 and first["has_more"]
    assert len(second["drafts"]) == 1 and not second["has_more"]
    assert not (
        {v["draft_id"] for v in first["drafts"]} & {v["draft_id"] for v in second["drafts"]}
    )
    bounded = client.get("/drafts?offset=50&limit=25").json()
    assert len(bounded["drafts"]) == 25 and bounded["has_more"]
    for query in ("offset=-1", "limit=0", "limit=201"):
        assert client.get(f"/drafts?{query}").status_code == 422


def test_concurrent_batch_requests_issue_one_approval(tmp_path):
    service = ApprovalService(ApprovalRepository())
    draft = prepare(service)
    client, token = client_for(tmp_path, service)
    client.cookies.set(SESSION_COOKIE, token)
    headers = {"X-CSRF-Token": client.get("/session").json()["csrf"]}

    def submit(_):
        return client.post(
            "/approvals/batch", json={"items": [item(draft)]}, headers=headers
        ).json()["results"][0]["status"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, range(2))) == ["already_approved", "approved"]
    assert len(service.repository.approvals) == 1


def test_execution_status_requires_login_and_preserves_approval_results(tmp_path):
    service = ApprovalService(ApprovalRepository())
    draft = prepare(service)
    client, token = client_for(tmp_path, service)
    assert client.get("/drafts?view=execution").status_code == 401
    client.cookies.set(SESSION_COOKIE, token)
    headers = {"X-CSRF-Token": client.get("/session").json()["csrf"]}
    client.post("/approvals/batch", json={"items": [item(draft)]}, headers=headers)
    assert client.get("/drafts").json()["drafts"] == []
    record = client.get("/drafts?view=execution").json()["drafts"][0]
    assert record["status"] == "approved" and record["approval"]["approved_by"] == "admin"
    assert record["review_packet"] is None
    assert service.repository.executions == {}


def test_select_all_snapshot_excludes_approved_expired_and_other_intents(tmp_path):
    service = ApprovalService(ApprovalRepository())
    expected = [prepare(service) for _ in range(205)]
    approved = prepare(service)
    prepare(service, lifetime=dt.timedelta(seconds=-1))
    prepare(service, IntentKind.ARCHIVE)
    service.approve(
        draft_id=approved.draft_id,
        payload_hash=approved.payload_hash,
        actor=Actor("admin", "approval-ui", "approval-ui", True),
    )
    client, token = client_for(tmp_path, service)
    assert client.get("/drafts?select_all=true").status_code == 401
    client.cookies.set(SESSION_COOKIE, token)
    value = client.get("/drafts?select_all=true").json()
    assert {item["draft_id"] for item in value["drafts"]} == {draft.draft_id for draft in expected}
    assert all(set(item) == {"draft_id", "payload_hash"} for item in value["drafts"])


def test_database_timeout_has_recoverable_response_and_timing_log(tmp_path, monkeypatch, caplog):
    service = ApprovalService(ApprovalRepository())
    client, token = client_for(tmp_path, service)
    client.cookies.set(SESSION_COOKIE, token)

    def unavailable(*_args, **_kwargs):
        raise psycopg.OperationalError("test database unavailable")

    monkeypatch.setattr(service.repository, "approval_rows", unavailable)
    with caplog.at_level("INFO", logger="uvicorn.error"):
        response = client.get("/drafts?select_all=true")
    assert response.status_code == 503
    assert "detail" in response.json()
    assert response.headers["x-request-id"] in caplog.text
    assert "duration_ms=" in caplog.text
    assert "test database unavailable" not in caplog.text
    assert client.get("/healthz").status_code == 200


HUMAN = Actor("admin", "approval-ui", "approval-ui", True)
DISPATCH_KINDS = ("archive", "mark", "move", "send", "trash")
DISPATCHER_UNAVAILABLE = "APPROVAL_DISPATCHER_UNAVAILABLE"


def dispatch_client_for(tmp_path, service, *, audit_recorder=None):
    """Return a logged-in client and CSRF headers with server dispatch enabled."""
    path = tmp_path / "session-key"
    path.write_text(base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode())
    path.chmod(0o600)
    token, _ = AdminSessionAuth(session_key_file=path).issue("admin")
    client = TestClient(
        create_app(
            Settings(
                approval_ui_enabled=True,
                admin_session_key_file=path,
                admin_secure_cookies=False,
                approval_dispatch_enabled=True,
            ),
            approvals=service,
            audit_recorder=audit_recorder,
        )
    )
    client.cookies.set(SESSION_COOKIE, token)
    return client, {"X-CSRF-Token": client.get("/session").json()["csrf"]}


def heartbeat(service, *, age=dt.timedelta(0), kinds=DISPATCH_KINDS):
    service.repository.record_dispatcher_status(
        host="host-a",
        kinds=list(kinds),
        last_scan_at=service.now() - age,
        last_error_class=None,
        last_item_error_class=None,
        last_result={},
    )


def prepare_message(service, stable_id):
    account = next(item for item in TEST_ACCOUNTS if item.alias == "gmail")
    return service.prepare(
        kind=IntentKind.TRASH,
        payload={
            "operation": "trash",
            "account": "gmail",
            "stable_message_id": stable_id,
            "source_folder": "INBOX",
            "source_uid": 7,
            "source_uid_validity": "777",
            "provider_message_id": f"{stable_id}@example.test",
            "raw_body_sha256": "b" * 64,
            "destination": account.trash_folder,
            "copy_preserve_source_fallback": False,
        },
        actor=Actor("agent", "codex", "mcp", False),
    )


def unavailable(response):
    return response.status_code == 503 and response.json()["detail"].startswith(
        DISPATCHER_UNAVAILABLE
    )


def test_dispatch_gate_rejects_missing_stale_or_kindless_heartbeat(tmp_path, fixed_now):
    clock = [fixed_now]
    service = ApprovalService(ApprovalRepository(), now=lambda: clock[0])
    single, batch = prepare(service), prepare(service)
    archive = prepare(service, IntentKind.ARCHIVE)
    client, headers = dispatch_client_for(tmp_path, service)

    def approve_single(draft):
        return client.post("/approvals", json=item(draft), headers=headers)

    def approve_batch():
        return client.post("/approvals/batch", json={"items": [item(batch)]}, headers=headers)

    assert client.get("/drafts").json()["approval_dispatch"]["ready"] is False
    assert unavailable(approve_single(single)) and unavailable(approve_batch())
    heartbeat(service, age=dt.timedelta(seconds=121))
    assert client.get(f"/drafts/{single.draft_id}").json()["approval_dispatch"]["ready"] is False
    assert unavailable(approve_single(single)) and unavailable(approve_batch())
    heartbeat(service, kinds=("archive", "mark", "move", "send"))
    assert unavailable(approve_single(single)) and unavailable(approve_batch())
    assert service.repository.approvals == {}
    assert approve_single(archive).status_code == 200

    heartbeat(service, age=dt.timedelta(seconds=120))
    dispatch = client.get("/drafts?view=execution").json()["approval_dispatch"]
    assert dispatch["enabled"] and dispatch["ready"] and dispatch["kinds"] == list(DISPATCH_KINDS)
    response = approve_single(single)
    assert response.status_code == 200 and response.json()["approval_source"] == "human"
    assert [r["status"] for r in approve_batch().json()["results"]] == ["approved"]
    assert len(service.repository.approvals) == 3


def test_revoke_records_audit_event_through_injected_recorder(tmp_path, fixed_now):
    clock = [fixed_now]
    service = ApprovalService(ApprovalRepository(), now=lambda: clock[0])
    waiting, confirmed = prepare(service), prepare(service)
    kept = service.approve(
        draft_id=waiting.draft_id, payload_hash=waiting.payload_hash, actor=HUMAN
    )
    done = service.approve(
        draft_id=confirmed.draft_id, payload_hash=confirmed.payload_hash, actor=HUMAN
    )
    service.repository.claim_execution(
        approval_id=done.approval_id,
        draft_id=confirmed.draft_id,
        kind=IntentKind.TRASH,
        payload_hash=confirmed.payload_hash,
        now=clock[0],
    )
    clock[0] += dt.timedelta(days=3)
    events = []

    def recorder(**event):
        events.append(event)
        return "audit-1"

    client, headers = dispatch_client_for(tmp_path, service, audit_recorder=recorder)
    body = {"items": [item(waiting), item(confirmed)]}
    assert client.post("/approvals/revoke", json=body).status_code == 403
    duplicate = {"items": [item(waiting), item(waiting)]}
    assert client.post("/approvals/revoke", json=duplicate, headers=headers).status_code == 400
    assert events == []

    response = client.post("/approvals/revoke", json=body, headers=headers)
    assert response.status_code == 200
    results = response.json()["results"]
    # Days later the approval is still open to revoke; the claimed one is not.
    assert [r["status"] for r in results] == ["revoked", "failed"]
    assert events == [
        {
            "event_type": "approval.revoked",
            "actor": "admin",
            "client_id": "approval-ui",
            "outcome": "SUCCESS",
            "metadata": {
                "count": 1,
                "revoked": [
                    {
                        "approval_id": kept.approval_id,
                        "draft_id": waiting.draft_id,
                        "previous_state": None,
                    }
                ],
            },
        }
    ]
    again = client.post("/approvals/revoke", json=body, headers=headers).json()["results"]
    assert [r["status"] for r in again] == ["failed", "failed"]
    assert len(events) == 1


def test_revoke_works_while_the_dispatcher_is_down(tmp_path):
    service = ApprovalService(ApprovalRepository())
    draft = prepare(service)
    service.approve(draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=HUMAN)
    client, headers = dispatch_client_for(tmp_path, service, audit_recorder=lambda **_: "")
    # No dispatcher heartbeat exists, yet revoking must still succeed.
    response = client.post("/approvals/revoke", json={"items": [item(draft)]}, headers=headers)
    assert response.status_code == 200
    assert [r["status"] for r in response.json()["results"]] == ["revoked"]
    assert service.review(draft.draft_id)["status"] == "revoked"


def test_execution_view_groups_every_status_into_four_phases(tmp_path):
    service = ApprovalService(ApprovalRepository())
    fence = SideEffectFence(FenceConfig("host-a", "host-a", 2, True, True))
    lease = LeaseToken("test", "slot", "host-a", 2, "nonce")
    names = ("waiting", "revoked", "retryable", "attempting", "confirmed", "failed", "unknown")
    drafts = {name: prepare_message(service, f"{index:024d}") for index, name in enumerate(names)}
    drafts["source_gone"] = prepare_message(service, "e" * 24)
    unapproved = prepare_message(service, "f" * 24)
    approvals = {
        name: service.approve(draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=HUMAN)
        for name, draft in drafts.items()
    }
    service.revoke(
        items=[(drafts["revoked"].draft_id, drafts["revoked"].payload_hash)], actor=HUMAN
    )
    service.repository.claim_execution(
        approval_id=approvals["attempting"].approval_id,
        draft_id=drafts["attempting"].draft_id,
        kind=IntentKind.TRASH,
        payload_hash=drafts["attempting"].payload_hash,
        now=service.now(),
    )

    def execute(name, provider):
        return service.execute(
            approval_id=approvals[name].approval_id,
            draft_id=drafts[name].draft_id,
            current_payload=drafts[name].payload,
            fence=fence,
            lease=lease,
            executor=provider,
        )

    def fail_with(error):
        def provider(*_):
            raise error

        return provider

    assert execute("confirmed", lambda *_: {})["state"] == "CONFIRMED"
    failures = {
        "retryable": ProviderNotAttempted("login failed"),
        "failed": ProviderDefinitelyRejected("identity mismatch"),
        "unknown": ProviderOutcomeUnknown("connection lost"),
        "source_gone": ProviderSourceGone("message moved elsewhere"),
    }
    for name, error in failures.items():
        with pytest.raises(type(error)):
            execute(name, fail_with(error))
    client, token = client_for(tmp_path, service)
    client.cookies.set(SESSION_COOKIE, token)
    by_id = {draft.draft_id: name for name, draft in drafts.items()}
    by_id[unapproved.draft_id] = "unapproved"

    def view(status):
        value = client.get(f"/drafts?view=execution&status={status}").json()
        return {
            by_id[d["draft_id"]]: (d["status"], d["phase"], d["revocable"]) for d in value["drafts"]
        }

    assert set(view("all")) == {*drafts, "unapproved"}
    # Only a fresh draft still needs a human; approvals never lapse back here.
    assert view("pending") == {
        "unapproved": ("pending_approval", "pending", False),
    }
    # Queued, in flight, or being verified by the server. Unclaimed work can be revoked.
    assert view("running") == {
        "waiting": ("approved", "running", True),
        "retryable": ("retryable", "running", True),
        "attempting": ("attempting", "running", False),
        "unknown": ("unknown", "running", False),
    }
    assert view("confirmed") == {"confirmed": ("confirmed", "confirmed", False)}
    # FAILED and revoked rows are final; recovery means preparing a fresh draft.
    assert view("failed") == {
        "failed": ("failed", "failed", False),
        "source_gone": ("failed", "failed", False),
        "revoked": ("revoked", "failed", False),
    }
    counts = client.get("/drafts?view=execution").json()["counts"]
    assert counts == {"all": 9, "pending": 1, "running": 4, "confirmed": 1, "failed": 3}
    for legacy in ("waiting", "expired", "unknown", "bogus"):
        assert client.get(f"/drafts?view=execution&status={legacy}").status_code == 422


def test_unexpected_drafts_error_returns_json_500_with_request_id(tmp_path, monkeypatch, caplog):
    service = ApprovalService(ApprovalRepository())
    client, token = client_for(tmp_path, service)
    client.cookies.set(SESSION_COOKIE, token)

    def broken(**_):
        raise KeyError("private subject line")

    monkeypatch.setattr(service, "pending_trash_page", broken)
    with caplog.at_level("ERROR", logger="uvicorn.error"):
        response = client.get("/drafts")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    value = response.json()
    assert value["reason_code"] == "SERVICE_UNAVAILABLE"
    assert value["detail"].startswith("The service is temporarily unavailable")
    assert value["request_id"] == response.headers["x-request-id"]
    assert f"request_id={value['request_id']}" in caplog.text
    assert "error_class=KeyError" in caplog.text
    assert "private subject line" not in response.text + caplog.text
