from __future__ import annotations

import base64
import contextlib
import datetime as dt
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest
from account_fixtures import TEST_ACCOUNTS
from fastapi.testclient import TestClient

from apps.approval_ui.main import create_app
from apps.mcp import main as mcp_app_module
from evergarden.approvals.models import Actor, IntentKind
from evergarden.approvals.service import ApprovalRepository, ApprovalService
from evergarden.auth.admin_session import SESSION_COOKIE, AdminSessionAuth
from evergarden.auth.models import Principal
from evergarden.auth.oauth_coordinator import OAuthStateError
from evergarden.auth.provider_oauth import MicrosoftConfigurationError
from evergarden.automations.fence import FenceRejected, LeaseToken
from evergarden.config import Settings
from evergarden.mail import runtime as runtime_module
from evergarden.mail.runtime import MailRuntime, MailSyncBatchError


class _RuntimeActionExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, payload: dict, _idempotency_key: str) -> dict:
        self.calls += 1
        return {
            "status": "confirmed",
            "operation": payload["operation"],
            "account": payload["account"],
            "provider_object_id": payload["message_id"],
            "message_id": payload["message_id"],
            "sent_copy_verified": True,
            "sent_copy_state": "verified",
        }

    def reconcile(self, _payload: dict, _idempotency_key: str) -> dict | None:
        raise AssertionError("reconciliation is not expected")

    def organization_capabilities(self, alias: str) -> dict:
        return {"account": alias, "native_move": True, "provider_mutations": 0}

    session = staticmethod(contextlib.nullcontext)


class _FakeMailRuntime:
    instances: ClassVar[list[_FakeMailRuntime]] = []

    def __init__(self, _settings: Settings):
        self.archive_reader = object()
        self.actions = _RuntimeActionExecutor()
        self.accounts = TEST_ACCOUNTS
        self.uidplus_move_accounts = frozenset()
        from evergarden.mail.policy import AccountPolicy

        self.policy = AccountPolicy(
            accounts=self.accounts,
            read_accounts=self.accounts,
            receive_only_accounts=frozenset(),
            uidplus_move_accounts=frozenset(),
        )
        self.store = object()
        self.staged_attachments = object()
        self.instances.append(self)

    def sync_selected(self, _account, *, per_folder_limit):
        return [{"limit": per_folder_limit}]

    def refresh_readiness(self):
        return []


def _prepare_and_approve_runtime_send(runtime):
    principal = Principal.build(
        subject="read-only:test",
        client_id="deployment-test",
        scopes={"mail:draft", "mail:send-approved"},
        audience="https://evergarden.test/mcp",
        issuer="https://auth.example.invalid",
    )
    draft = runtime.call(
        "prepare_send",
        {
            "account": "gmail",
            "to": ["recipient@example.test"],
            "subject": "Runtime wiring",
            "body": "Approved body",
        },
        principal,
    )
    approval = runtime.approvals.approve(
        draft_id=draft["draft_id"],
        payload_hash=draft["payload_hash"],
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )
    return principal, draft, approval


def _admin_session(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "admin-session-key"
    value = base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode()
    path.write_text(value)
    path.chmod(0o600)
    token, _session = AdminSessionAuth(session_key_file=path).issue("admin")
    return path, token


def test_approval_ui_is_disabled_by_default_and_requires_admin_session(
    tmp_path: Path,
) -> None:
    service = ApprovalService(ApprovalRepository())
    draft = service.prepare(
        kind=IntentKind.SEND,
        payload={
            "operation": "send",
            "account": "gmail",
            "from": "sender@example.test",
            "to": ["x@example.test"],
            "subject": "Draft",
            "body": "Body",
            "date": "2026-08-17T12:00:00+00:00",
            "message_id": "<draft@example.test>",
        },
        actor=Actor("agent", "codex", "mcp", False),
    )
    disabled = TestClient(create_app(Settings(), approvals=service))
    assert disabled.get("/healthz").json()["enabled"] is False
    assert (
        disabled.post(
            "/approvals", json={"draft_id": draft.draft_id, "payload_hash": draft.payload_hash}
        ).status_code
        == 503
    )

    session_path, token = _admin_session(tmp_path)
    settings = Settings(
        approval_ui_enabled=True,
        admin_session_key_file=session_path,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, approvals=service))
    body = {"draft_id": draft.draft_id, "payload_hash": draft.payload_hash}
    assert client.post("/approvals", json=body).status_code == 401
    assert client.get(f"/drafts/{draft.draft_id}").status_code == 401
    forged = {"Remote-User": "admin", "Remote-Groups": "evergarden-admins"}
    assert client.get(f"/drafts/{draft.draft_id}", headers=forged).status_code == 401
    redirect = client.get("/review", follow_redirects=False)
    assert redirect.status_code == 303
    assert redirect.headers["location"] == "/login?next=%2Freview"
    send_redirect = client.get("/review/send?draft_id=test", follow_redirects=False)
    assert send_redirect.status_code == 303
    assert send_redirect.headers["location"] == "/login?next=%2Freview%2Fsend%3Fdraft_id%3Dtest"
    client.cookies.set(SESSION_COOKIE, token)
    review = client.get(f"/drafts/{draft.draft_id}")
    assert review.status_code == 200
    assert review.json()["review_packet"] == draft.payload
    assert client.get("/review").status_code == 200
    send_page = client.get("/review/send")
    assert send_page.status_code == 200
    assert 'data-i18n="send.body"' in send_page.text
    assert client.get("/assets/send.js").status_code == 200
    assert client.get("/assets/approval.css").status_code == 200
    assert client.get("/assets/missing").status_code == 404
    assert client.get("/drafts/missing").status_code == 404
    assert client.get("/session?surface=unknown").status_code == 400
    session = client.get("/session?surface=approval").json()
    approved = client.post(
        "/approvals",
        json=body,
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert approved.status_code == 200
    assert approved.json()["approved_by"] == "admin"


class FakeOAuth:
    clients: ClassVar[dict[str, object]] = {
        "work": object(),
        "device": SimpleNamespace(
            provider="microsoft", configured=False, flow="device_code", app_name="Example Mail"
        ),
    }

    def start(self, account: str):
        if account == "bad":
            raise OAuthStateError("unknown")
        if account == "device":
            raise MicrosoftConfigurationError("register your own Microsoft Entra app")
        return {"authorization_url": "https://login.test", "state": "state"}

    def callback(self, *, state: str, code: str, provider: str = "microsoft"):
        if state == "bad":
            raise OAuthStateError("invalid")
        return {"account": "work", "status": "authorized", "code_seen": bool(code)}

    def poll_device(self, flow_id: str):
        return {"account": "work", "status": "authorization_pending", "interval": 5}


def test_oauth_ui_callback_framework_is_fenced_and_human_admin_only(tmp_path: Path) -> None:
    disabled = TestClient(create_app(Settings(), oauth=FakeOAuth()))
    assert disabled.post("/oauth/start/work").status_code == 503
    assert disabled.post("/oauth/device/poll", json={"flow_id": "x" * 32}).status_code == 503
    assert disabled.get("/oauth/callback/microsoft?state=x&code=y").status_code == 503

    session_path, token = _admin_session(tmp_path)
    settings = Settings(
        oauth_callback_enabled=True,
        admin_session_key_file=session_path,
        admin_secure_cookies=False,
    )
    enabled = TestClient(create_app(settings, oauth=FakeOAuth()))
    assert enabled.post("/oauth/start/work").status_code == 401
    assert enabled.post("/oauth/device/poll", json={"flow_id": "x" * 32}).status_code == 401
    assert enabled.get("/oauth", follow_redirects=False).status_code == 303
    enabled.cookies.set(SESSION_COOKIE, token)
    assert enabled.get("/oauth").status_code == 200
    assert enabled.get("/oauth/accounts").json() == {
        "accounts": ["device", "work"],
        "providers": {"work": "microsoft", "device": "microsoft"},
        "configured": {"work": True, "device": False},
        "flows": {"work": "authorization_code", "device": "device_code"},
        "app_names": {"work": "", "device": "Example Mail"},
    }
    assert enabled.get("/assets/oauth.js").status_code == 200
    csrf = enabled.get("/session?surface=oauth").json()["csrf"]
    assert enabled.post("/oauth/device/poll", json={"flow_id": "x" * 32}).status_code == 403
    polled = enabled.post(
        "/oauth/device/poll", json={"flow_id": "x" * 32}, headers={"X-CSRF-Token": csrf}
    )
    assert polled.json()["status"] == "authorization_pending"
    started = enabled.post(
        "/oauth/start/work",
        headers={"X-CSRF-Token": csrf},
    )
    assert started.status_code == 200
    assert started.json()["state"] == "state"
    unconfigured = enabled.post("/oauth/start/device", headers={"X-CSRF-Token": csrf})
    assert unconfigured.status_code == 503
    assert "register your own Microsoft Entra app" in unconfigured.json()["detail"]
    assert (
        enabled.post(
            "/oauth/start/bad",
            headers={"X-CSRF-Token": csrf},
        ).status_code
        == 400
    )
    assert enabled.get("/oauth/callback/microsoft?state=x&error=denied").status_code == 400
    assert enabled.get("/oauth/callback/microsoft?state=x").status_code == 503
    assert enabled.get("/oauth/callback/microsoft?state=bad&code=y").status_code == 400
    callback = enabled.get(
        "/oauth/callback/microsoft?state=x&code=y",
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"].startswith("/oauth?status=authorized")


def test_one_admin_session_unlocks_approval_and_oauth_without_proxy_groups(
    tmp_path: Path,
) -> None:
    session_path, token = _admin_session(tmp_path)
    settings = Settings(
        approval_ui_enabled=True,
        oauth_callback_enabled=True,
        admin_session_key_file=session_path,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, approvals=ApprovalService(ApprovalRepository())))
    client.cookies.set(SESSION_COOKIE, token)

    assert client.get("/review").status_code == 200
    assert client.get("/oauth").status_code == 200
    assert client.get("/assets/approval.css").status_code == 200
    client.cookies.clear()
    assert client.get("/assets/approval.css").status_code == 401


def test_mail_runtime_uses_host_store_and_four_account_adapters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evergarden.auth.credential_store import encode_key, generate_key

    key_file = tmp_path / "secrets" / "key"
    key_file.parent.mkdir()
    key_file.write_text(encode_key(generate_key()))
    key_file.chmod(0o600)
    settings = Settings(
        archive_dir=tmp_path / "archive",
        credential_db=tmp_path / "secrets" / "credentials.db",
        credential_key_file=key_file,
        oauth_jwks_url=None,
    )
    runtime = MailRuntime(settings, accounts=TEST_ACCOUNTS)
    assert set(runtime.oauth_clients) == {"work", "outlook"}

    class FakeSync:
        def sync_account(self, account, *, per_folder_limit):
            return {"account": account.alias, "limit": per_folder_limit}

    runtime.sync = FakeSync()
    results = runtime.sync_all(per_folder_limit=7)
    assert [item["account"] for item in results] == [
        "work",
        "outlook",
        "gmail",
        "icloud",
    ]
    assert {item["limit"] for item in results} == {7}

    attempts: list[str] = []

    class PartiallyFailingSync:
        def sync_account(self, account, *, per_folder_limit):
            attempts.append(account.alias)
            if account.alias == "outlook":
                raise RuntimeError("provider unavailable")
            return {"account": account.alias, "limit": per_folder_limit}

    runtime.sync = PartiallyFailingSync()
    with pytest.raises(MailSyncBatchError) as selected_failure:
        runtime.sync_selected("outlook", per_folder_limit=9)
    assert selected_failure.value.results == []
    assert selected_failure.value.failures[0]["account"] == "outlook"
    assert selected_failure.value.failures[0]["error_detail"] == "provider unavailable"
    attempts.clear()
    with pytest.raises(MailSyncBatchError) as failure:
        runtime.sync_all(per_folder_limit=9)
    assert attempts == ["work", "outlook", "gmail", "icloud"]
    assert [item["account"] for item in failure.value.results] == [
        "work",
        "gmail",
        "icloud",
    ]
    assert failure.value.failures == [
        {
            "account": "outlook",
            "error_class": "RuntimeError",
            "error_detail": "provider unavailable",
        }
    ]

    class PartiallyIncompleteSync:
        def sync_account(self, account, *, per_folder_limit):
            assert per_folder_limit == 456
            if account.alias == "outlook":
                raise runtime_module.MailboxSyncIncomplete(
                    {"account": account.alias, "inserted": 1, "folders": {}},
                    ({"folder": "Archive", "error_class": "RuntimeError"},),
                )
            if account.alias == "gmail":
                raise OSError("provider unavailable")
            return {"account": account.alias, "inserted": 2, "folders": {}}

    runtime.sync = PartiallyIncompleteSync()
    with pytest.raises(MailSyncBatchError) as incomplete_failure:
        runtime.sync_all(per_folder_limit=456)
    assert [item["account"] for item in incomplete_failure.value.results] == [
        "work",
        "outlook",
        "icloud",
    ]
    assert incomplete_failure.value.failures == [
        {
            "account": "outlook",
            "error_class": "MailboxSyncIncomplete",
            "error_detail": "mailbox sync incomplete for outlook: 1 folder(s)",
            "failed_folders": [
                {"folder": "Archive", "error_class": "RuntimeError", "error_detail": ""}
            ],
        },
        {
            "account": "gmail",
            "error_class": "OSError",
            "error_detail": "provider unavailable",
        },
    ]

    class FakeClient:
        def __init__(self, record_id: str):
            self.record_id = record_id
            self.calls = 0

        def access_token(self, *, refresh_margin_seconds: int):
            assert refresh_margin_seconds == 1800
            self.calls += 1
            return "redacted"

    runtime.store.put("microsoft:work", {"access_token": "x"})
    runtime.store.put("microsoft:outlook", {"access_token": "y"})
    clients = {
        "work": FakeClient("microsoft:work"),
        "outlook": FakeClient("microsoft:outlook"),
    }
    runtime.oauth_clients = clients
    assert runtime.oauth_access_token(TEST_ACCOUNTS[0]) == "redacted"

    runtime.store.put(
        "microsoft:work",
        {
            "access_token": "x",
            "refresh_token": "r",
            "expires_at": (dt.datetime.now(dt.UTC) + dt.timedelta(hours=2)).isoformat(),
        },
    )
    runtime.store.put(
        "microsoft:outlook",
        {"refresh_token": "r", "expires_at": "malformed"},
    )
    readiness = {item["account"]: item for item in runtime.refresh_readiness()}
    assert readiness["work"]["has_refresh_token"] is True
    assert readiness["work"]["would_refresh_within_hour"] is False
    assert readiness["outlook"]["access_token_expired"] is True
    assert readiness["outlook"]["has_access_token"] is False
    assert readiness["outlook"]["status"] == "refresh_required"
    runtime.store.put(
        "microsoft:work",
        {
            "access_token": "x",
            "refresh_token": "r",
            "expires_at": (dt.datetime.now(dt.UTC) + dt.timedelta(hours=2)).isoformat(),
            "oauth_failure": {
                "error": "invalid_grant",
                "error_codes": [70043],
                "reauthorization_required": True,
            },
        },
    )
    expired_grant = {item["account"]: item for item in runtime.refresh_readiness()}["work"]
    assert expired_grant["status"] == "authorization_required"
    assert expired_grant["last_refresh_error_codes"] == [70043]
    runtime.oauth_clients["new-account"] = FakeClient("microsoft:new-account")
    missing = {item["account"]: item for item in runtime.refresh_readiness()}["new-account"]
    assert missing == {
        "account": "new-account",
        "status": "authorization_required",
        "has_refresh_token": False,
        "has_access_token": False,
        "access_token_expired": True,
        "would_refresh_within_hour": True,
    }


def test_default_mcp_runtime_read_only_fence_precedes_real_action_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeMailRuntime.instances.clear()
    repository = ApprovalRepository()
    monkeypatch.setattr(
        mcp_app_module,
        "PostgresApprovalRepository",
        lambda *_args, **_kwargs: repository,
    )
    monkeypatch.setattr(mcp_app_module, "read_key_file", lambda _path: b"x" * 32)
    monkeypatch.setattr(mcp_app_module, "CompositeVerifier", lambda _verifiers: object())
    monkeypatch.setattr(mcp_app_module, "MailRuntime", _FakeMailRuntime)

    _verifier, runtime, _audit = mcp_app_module._default_runtime(
        Settings(host_id="host-a", side_effects_enabled=False)
    )
    principal, draft, approval = _prepare_and_approve_runtime_send(runtime)

    with pytest.raises(FenceRejected, match="side effects are disabled"):
        runtime.call(
            "send_approved",
            {
                "approval_id": approval.approval_id,
                "draft_id": draft["draft_id"],
                "payload": draft["review_packet"],
            },
            principal,
        )

    assert _FakeMailRuntime.instances[-1].actions.calls == 0
    assert repository.approvals[approval.approval_id].consumed_at is None
    assert repository.executions == {}


def test_default_mcp_runtime_production_path_requires_database_writer_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeMailRuntime.instances.clear()
    repository = ApprovalRepository()
    lease_calls: list[dict[str, object]] = []

    @contextlib.contextmanager
    def fake_writer_action_lease(
        database_url: str, *, action_slot: str, host: str, owner_epoch: int
    ):
        lease_calls.append(
            {
                "database_url": database_url,
                "action_slot": action_slot,
                "host": host,
                "owner_epoch": owner_epoch,
            }
        )
        yield LeaseToken(
            job_id="approved-mail-action",
            scheduled_slot=action_slot,
            owner_host=host,
            writer_epoch=owner_epoch,
            nonce="test-lease",
        )

    monkeypatch.setattr(
        mcp_app_module,
        "PostgresApprovalRepository",
        lambda *_args, **_kwargs: repository,
    )
    monkeypatch.setattr(mcp_app_module, "read_key_file", lambda _path: b"x" * 32)
    monkeypatch.setattr(mcp_app_module, "CompositeVerifier", lambda _verifiers: object())
    monkeypatch.setattr(mcp_app_module, "MailRuntime", _FakeMailRuntime)
    monkeypatch.setattr(mcp_app_module, "writer_action_lease", fake_writer_action_lease)
    settings = Settings(
        host_id="host-a",
        active_writer="host-a",
        writer_epoch=7,
        side_effects_enabled=True,
    )

    _verifier, runtime, _audit = mcp_app_module._default_runtime(settings)
    principal, draft, approval = _prepare_and_approve_runtime_send(runtime)
    result = runtime.call(
        "send_approved",
        {
            "approval_id": approval.approval_id,
            "draft_id": draft["draft_id"],
            "payload": draft["review_packet"],
        },
        principal,
    )

    assert result["state"] == "CONFIRMED"
    assert _FakeMailRuntime.instances[-1].actions.calls == 1
    assert lease_calls == [
        {
            "database_url": settings.database_url,
            "action_slot": approval.approval_id,
            "host": "host-a",
            "owner_epoch": 7,
        }
    ]


def test_draft_message_endpoint_returns_full_archived_mail(
    tmp_path: Path, archive_dir: Path
) -> None:
    from evergarden.archive.reader import ArchiveReader

    service = ApprovalService(ApprovalRepository())
    actor = Actor("agent", "codex", "mcp", False)
    archive = service.prepare(
        kind=IntentKind.ARCHIVE,
        payload={
            "operation": "archive",
            "account": "outlook",
            "source_folder": "Inbox",
            "source_uid": 2,
            "source_uid_validity": "888",
            "destination": "Archive",
            "copy_preserve_source_fallback": False,
            "stable_message_id": "b" * 24,
            "raw_body_sha256": "f" * 64,
        },
        actor=actor,
    )
    missing = service.prepare(
        kind=IntentKind.ARCHIVE,
        payload={
            "operation": "archive",
            "account": "outlook",
            "source_folder": "Inbox",
            "source_uid": 3,
            "source_uid_validity": "888",
            "destination": "Archive",
            "copy_preserve_source_fallback": False,
            "stable_message_id": "c" * 24,
            "raw_body_sha256": "e" * 64,
        },
        actor=actor,
    )
    session_path, token = _admin_session(tmp_path)
    settings = Settings(
        approval_ui_enabled=True, admin_session_key_file=session_path, admin_secure_cookies=False
    )
    client = TestClient(
        create_app(settings, approvals=service, archive_reader=ArchiveReader(archive_dir))
    )
    url = f"/drafts/{archive.draft_id}/message"
    assert client.get(url).status_code == 401
    client.cookies.set(SESSION_COOKIE, token)
    value = client.get(url).json()
    assert value["available"] is True
    message = value["message"]
    assert message["subject"] == "Lunch"
    assert message["hash_matches"] is True
    assert "raw_body_sha256" not in message
    assert "this-must-never-leak" not in message["body_text"]
    assert client.get(f"/drafts/{missing.draft_id}/message").json() == {
        "available": False,
        "reason": "not_archived",
    }
    assert client.get("/drafts/missing/message").status_code == 404
