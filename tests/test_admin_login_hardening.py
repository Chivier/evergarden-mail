from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from test_mail_admin_ui import FakeGateway, _admin_files, _private

from apps.approval_ui.main import create_app as create_approval_app
from apps.mail_ui import main as mail_ui_module
from apps.mail_ui.main import create_app
from evergarden.approvals.service import ApprovalRepository, ApprovalService
from evergarden.auth.admin_session import (
    SECURE_SESSION_COOKIE,
    SESSION_COOKIE,
    AdminAuthError,
    AdminSessionAuth,
)
from evergarden.config import Settings


def _settings(tmp_path: Path, **overrides) -> Settings:
    credential_file, session_key_file, _password = _admin_files(tmp_path)
    values = {
        "mail_ui_enabled": True,
        "mail_ui_mcp_token_file": _private(tmp_path / "token", "mcp-token-" + "y" * 48),
        "admin_credential_file": credential_file,
        "admin_session_key_file": session_key_file,
        "admin_secure_cookies": False,
    }
    return Settings(**{**values, **overrides})


class BlockingAuth(AdminSessionAuth):
    """Real session handling with a password check the test can hold open."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(
            session_key_file=settings.admin_session_key_file,
            credential_file=settings.admin_credential_file,
            ttl_seconds=settings.admin_session_ttl_seconds,
        )
        self.release = threading.Event()
        self.started = threading.Semaphore(0)
        self.calls = 0
        self.threads: set[int] = set()

    def verify_login(self, username: str, password: str) -> str:
        self.calls += 1
        self.threads.add(threading.get_ident())
        self.started.release()
        self.release.wait(5)
        raise AdminAuthError("invalid administrator credentials")


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://mail.test")


WRONG = {"username": "admin", "password": "wrong-password-long"}


async def test_password_check_runs_off_the_event_loop(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    auth = BlockingAuth(settings)
    app = create_app(settings, gateway=FakeGateway(), admin_auth=auth)
    async with _client(app) as client:
        login = asyncio.create_task(client.post("/api/login", json=WRONG))
        assert await asyncio.to_thread(auth.started.acquire, True, 2)
        # The loop still answers while the scrypt check is in progress.
        health = await asyncio.wait_for(client.get("/healthz"), timeout=2)
        assert health.status_code == 200
        assert not login.done()
        auth.release.set()
        assert (await login).status_code == 401
    assert threading.get_ident() not in auth.threads


async def test_saturated_password_checks_answer_429_quickly(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(mail_ui_module, "LOGIN_SLOT_WAIT_SECONDS", 0.05)
    settings = _settings(tmp_path)
    auth = BlockingAuth(settings)
    app = create_app(settings, gateway=FakeGateway(), admin_auth=auth)
    async with _client(app) as client:
        running = [
            asyncio.create_task(client.post("/api/login", json=WRONG))
            for _ in range(mail_ui_module.LOGIN_CONCURRENCY)
        ]
        for _ in running:
            assert await asyncio.to_thread(auth.started.acquire, True, 2)
        started = time.monotonic()
        rejected = await client.post("/api/login", json=WRONG)
        assert time.monotonic() - started < 1
        assert rejected.status_code == 429
        assert rejected.headers["retry-after"] == "1"
        # The refused attempt never reached scrypt.
        assert auth.calls == mail_ui_module.LOGIN_CONCURRENCY
        auth.release.set()
        assert [(await task).status_code for task in running] == [401, 401]
        # Slots are returned, so the next attempt is checked normally.
        assert (await client.post("/api/login", json=WRONG)).status_code == 401
    assert auth.calls == mail_ui_module.LOGIN_CONCURRENCY + 1


async def test_throttled_requester_is_refused_before_any_password_check(tmp_path: Path) -> None:
    settings = _settings(tmp_path, admin_login_max_failures=3)
    auth = BlockingAuth(settings)
    auth.release.set()
    app = create_app(settings, gateway=FakeGateway(), admin_auth=auth)
    async with _client(app) as client:
        statuses = [(await client.post("/api/login", json=WRONG)).status_code for _ in range(5)]
    assert statuses == [401, 401, 401, 429, 429]
    assert auth.calls == 3


# --- Logout revokes sessions server-side ---------------------------------------


def _web_settings(tmp_path: Path, *, secure: bool = False) -> Settings:
    return _settings(
        tmp_path,
        admin_secure_cookies=secure,
        approval_ui_enabled=True,
        mail_ui_approval_url="https://mail.test" if secure else "http://127.0.0.1:8788",
        admin_session_revocation_file=tmp_path / "mail-config" / "revocations.json",
    )


def _approval_client(settings: Settings, tmp_path: Path) -> TestClient:
    return TestClient(
        create_approval_app(
            settings.model_copy(update={"archive_dir": tmp_path}),
            approvals=ApprovalService(ApprovalRepository()),
        )
    )


def _password(tmp_path: Path) -> str:
    return _admin_files(tmp_path)[2]


def test_logout_revokes_a_copied_cookie_on_both_browser_surfaces(tmp_path: Path) -> None:
    settings = _web_settings(tmp_path)
    mail = TestClient(create_app(settings, gateway=FakeGateway()))
    login = mail.post("/api/login", json={"username": "admin", "password": _password(tmp_path)})
    assert login.status_code == 200
    stolen = mail.cookies[SESSION_COOKIE]
    csrf = mail.get("/api/session").json()["csrf"]

    thief_mail = TestClient(create_app(settings, gateway=FakeGateway()))
    thief_mail.cookies.set(SESSION_COOKIE, stolen)
    thief_approval = _approval_client(settings, tmp_path)
    thief_approval.cookies.set(SESSION_COOKIE, stolen)
    assert thief_mail.get("/api/session").status_code == 200
    assert thief_approval.get("/session").status_code == 200

    assert mail.post("/api/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert settings.admin_session_revocation_file.stat().st_mode & 0o077 == 0
    assert thief_mail.get("/api/session").status_code == 401
    assert thief_approval.get("/session").status_code == 401
    assert (
        thief_approval.post(
            "/approvals/revoke", json={"items": [{"draft_id": "d", "payload_hash": "h"}]}
        ).status_code
        == 401
    )

    # Logging in again right away yields a session that works everywhere.
    again = TestClient(create_app(settings, gateway=FakeGateway()))
    assert (
        again.post(
            "/api/login", json={"username": "admin", "password": _password(tmp_path)}
        ).status_code
        == 200
    )
    assert again.get("/api/session").status_code == 200
    fresh = _approval_client(settings, tmp_path)
    fresh.cookies.set(SESSION_COOKIE, again.cookies[SESSION_COOKIE])
    assert fresh.get("/session").status_code == 200


def test_login_in_the_same_second_as_a_logout_outlives_it(tmp_path: Path) -> None:
    credential_file, session_key_file, _password = _admin_files(tmp_path)
    now = [1_800_000_000.0]
    auth = AdminSessionAuth(
        session_key_file=session_key_file,
        credential_file=credential_file,
        revocation_file=tmp_path / "state" / "revocations.json",
        clock=lambda: now[0],
    )
    before, _ = auth.issue("admin")
    auth.revoke("admin")
    with pytest.raises(AdminAuthError, match="signed out"):
        auth.authenticate(before)
    after, session = auth.issue("admin")
    assert auth.authenticate(after) == session
    now[0] += 0.5
    auth.revoke("admin")
    with pytest.raises(AdminAuthError, match="signed out"):
        auth.authenticate(after)
    # A revocation for one subject leaves another alone.
    other, other_session = auth.issue("operator")
    assert auth.authenticate(other) == other_session


def test_unsafe_revocation_list_fails_closed_and_unrecorded_logout_says_so(
    tmp_path: Path,
) -> None:
    credential_file, session_key_file, _password = _admin_files(tmp_path)
    path = tmp_path / "revocations.json"
    auth = AdminSessionAuth(
        session_key_file=session_key_file,
        credential_file=credential_file,
        revocation_file=path,
    )
    token, session = auth.issue("admin")
    assert auth.authenticate(token) == session
    path.write_text('{"version": 1, "not_before": {}}')
    path.chmod(0o644)
    with pytest.raises(AdminAuthError, match="unreadable"):
        auth.authenticate(token)
    path.chmod(0o600)
    assert auth.authenticate(token) == session
    path.write_text('{"version": 1, "not_before": {"admin": "soon"}}')
    with pytest.raises(AdminAuthError, match="malformed"):
        auth.authenticate(token)
    path.unlink()
    assert auth.authenticate(token) == session

    # A logout the server cannot record still clears the cookie but reports it.
    real = tmp_path / "real-directory"
    real.mkdir()
    blocked = tmp_path / "symlinked-directory"
    blocked.symlink_to(real)
    settings = _settings(tmp_path, admin_session_revocation_file=blocked / "revocations.json")
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    assert (
        client.post(
            "/api/login", json={"username": "admin", "password": _admin_files(tmp_path)[2]}
        ).status_code
        == 200
    )
    csrf = client.get("/api/session").json()["csrf"]
    response = client.post("/api/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 503
    assert response.json()["reason_code"] == "LOGOUT_NOT_RECORDED"
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_secure_sessions_use_the_host_prefixed_cookie(tmp_path: Path) -> None:
    settings = _web_settings(tmp_path, secure=True)
    mail = TestClient(create_app(settings, gateway=FakeGateway()), base_url="https://mail.test")
    login = mail.post("/api/login", json={"username": "admin", "password": _password(tmp_path)})
    assert login.status_code == 200
    header = login.headers["set-cookie"]
    assert header.startswith(f"{SECURE_SESSION_COOKIE}=")
    assert "Secure" in header and "Path=/" in header and "Domain" not in header
    token = mail.cookies[SECURE_SESSION_COOKIE]
    assert mail.get("/api/session").status_code == 200

    approval = _approval_client(settings, tmp_path)
    approval.cookies.set(SESSION_COOKIE, token)
    assert approval.get("/session").status_code == 401
    approval.cookies.clear()
    approval.cookies.set(SECURE_SESSION_COOKIE, token)
    assert approval.get("/session").status_code == 200


# --- MCP guide discovery -------------------------------------------------------


def test_mail_ui_offers_oauth_only_when_mcp_can_verify_oauth_tokens(tmp_path: Path) -> None:
    for jwks, expected in ((None, False), ("https://auth.test/jwks.json", True)):
        settings = _settings(tmp_path, oauth_issuer="https://auth.test", oauth_jwks_url=jwks)
        assert settings.oauth_bearer_enabled is expected
        client = TestClient(create_app(settings, gateway=FakeGateway()))
        assert (
            client.post(
                "/api/login", json={"username": "admin", "password": _password(tmp_path)}
            ).status_code
            == 200
        )
        session = client.get("/api/session").json()
        assert session["mcp_oauth_enabled"] is expected
        assert session["oauth_issuer"] == ("https://auth.test/" if expected else None)
