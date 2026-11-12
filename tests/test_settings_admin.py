from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_mail_admin_ui import FakeGateway, _account, _admin_files

from apps.approval_ui.main import create_app as approval_app
from apps.mail_ui.main import create_app
from evergarden.approvals.service import ApprovalRepository, ApprovalService
from evergarden.auth.credential_store import CredentialStore, encode_key, generate_key
from evergarden.config import Settings, get_settings
from evergarden.mail.account_admin import (
    AccountAdminError,
    AccountConfigConflict,
    AccountConfigManager,
)
from evergarden.runtime_settings import (
    RuntimeSettingsConflict,
    RuntimeSettingsError,
    RuntimeSettingsManager,
)


def _settings(tmp_path: Path) -> Settings:
    credential_file, session_file, _password = _admin_files(tmp_path)
    key_file = tmp_path / "credential_key"
    key_file.write_text(encode_key(generate_key()))
    key_file.chmod(0o600)
    return Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=tmp_path / "mail_ui_token",
        approval_ui_enabled=True,
        oauth_callback_enabled=True,
        mail_ui_account_admin_enabled=True,
        mail_ui_api_keys_enabled=True,
        account_config_file=tmp_path / "config" / "accounts.json",
        mcp_api_keys_file=tmp_path / "keys" / "keys.json",
        credential_key_file=key_file,
        credential_db=tmp_path / "private" / "credentials.db",
        admin_credential_file=credential_file,
        admin_session_key_file=session_file,
        admin_session_revocation_file=tmp_path / "revocations.json",
        admin_secure_cookies=False,
    )


def _client(settings: Settings) -> tuple[TestClient, dict]:
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    assert (
        client.post(
            "/api/login", json={"username": "admin", "password": "correct horse battery staple"}
        ).status_code
        == 200
    )
    return client, {"X-CSRF-Token": client.get("/api/session").json()["csrf"]}


def test_settings_are_private_revision_checked_and_loaded_on_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    manager = RuntimeSettingsManager(settings)
    original = manager.snapshot()
    updated = manager.update(
        {"admin_login_max_failures": 15, "schedule_timezone": "Europe/Paris"},
        expected_revision=original["revision"],
    )
    assert updated["restart_required"] is True
    assert settings.schedule_timezone == "UTC"
    assert manager.store.path.stat().st_mode & 0o077 == 0
    assert "database_url" not in json.dumps(updated)
    assert "credential_key" not in json.dumps(updated)
    with pytest.raises(RuntimeSettingsConflict):
        manager.update({"log_level": "ERROR"}, expected_revision=original["revision"])
    monkeypatch.setenv("EVERGARDEN_ACCOUNT_CONFIG_FILE", str(settings.account_config_file))
    get_settings.cache_clear()
    try:
        restarted = get_settings()
        assert restarted.schedule_timezone == "Europe/Paris"
        assert RuntimeSettingsManager(restarted).snapshot()["restart_required"] is False
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize(
    "changes",
    [
        {"host_id": "other"},
        {"database_url": "postgresql://other"},
        {"credential_key_file": "/tmp/key"},
        {"admin_login_max_failures": 0},
        {"admin_login_max_failures": True},
        {"admin_login_max_failures": "15"},
        {"schedule_timezone": "Mars/Unknown"},
        {"auto_approve": "trash"},
        {"auto_approve": "all,trash"},
        {"log_level": "injected\nvalue"},
        {"log_level": "INVALID"},
    ],
)
def test_invalid_runtime_configuration_never_overwrites_existing_file(
    tmp_path: Path, changes: dict
) -> None:
    manager = RuntimeSettingsManager(_settings(tmp_path))
    snapshot = manager.snapshot()
    saved = manager.update({"log_level": "INFO"}, expected_revision=snapshot["revision"])
    before = manager.store.path.read_bytes()
    with pytest.raises(RuntimeSettingsError):
        manager.update(changes, expected_revision=saved["revision"], acknowledge_risk=True)
    assert manager.store.path.read_bytes() == before


def test_write_permission_changes_require_confirmation_and_keep_trash_human_gated(
    tmp_path: Path,
) -> None:
    manager = RuntimeSettingsManager(_settings(tmp_path))
    snapshot = manager.snapshot()
    with pytest.raises(RuntimeSettingsError, match="acknowledgement"):
        manager.update({"auto_approve": "all"}, expected_revision=snapshot["revision"])
    manager.update(
        {"auto_approve": "all"}, expected_revision=snapshot["revision"], acknowledge_risk=True
    )
    assert "trash" not in manager.configured().auto_approve_kinds


def test_mailbox_edit_remove_preserves_other_accounts_and_rejects_invalid_changes(
    tmp_path: Path,
) -> None:
    manager = AccountConfigManager(tmp_path / "config" / "accounts.json")
    first = manager.add(_account(), expected_revision=manager.snapshot()["revision"])
    both = manager.add(_account("other"), expected_revision=first["revision"])
    other = both["accounts"][1]
    changed = manager.update(
        "work",
        {
            "imap_host": "new.example.com",
            "imap_port": 1993,
            "folders": ["INBOX", "Archive", "Projects"],
        },
        expected_revision=both["revision"],
    )
    assert changed["accounts"][0]["imap_port"] == 1993
    assert changed["accounts"][0]["credential_record"] == "microsoft:work"
    assert changed["accounts"][1] == other
    with pytest.raises(AccountConfigConflict):
        manager.update("work", {}, expected_revision=both["revision"])
    for changes in (
        {"alias": "renamed"},
        {"password": "rejected"},
        {"safe_move_folders": ["Trash"]},
        {"address": other["address"]},
    ):
        with pytest.raises(AccountAdminError):
            manager.update("work", changes, expected_revision=changed["revision"])
    with pytest.raises(AccountAdminError):
        manager.remove("work", expected_revision=changed["revision"], confirmation="other")
    removed = manager.remove("work", expected_revision=changed["revision"], confirmation="work")
    assert removed["accounts"] == [other]


def test_settings_page_and_mutation_endpoints_require_admin_and_csrf(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    assert (
        client.get("/settings", follow_redirects=False).headers["location"]
        == "/login?next=%2Fsettings"
    )
    assert client.get("/assets/settings.js").status_code == 401
    assert client.get("/api/admin/settings").status_code == 401
    client, headers = _client(settings)
    assert client.get("/settings").status_code == 200
    snapshot = client.get("/api/admin/settings").json()
    body = {"expected_revision": snapshot["revision"], "changes": {"admin_login_max_failures": 16}}
    assert client.patch("/api/admin/settings", json=body).status_code == 403
    assert client.patch("/api/admin/settings", json=body, headers=headers).status_code == 200
    assert client.patch("/api/admin/settings", json=body, headers=headers).status_code == 409
    rev = client.get("/api/admin/accounts").json()["revision"]
    added = client.post(
        "/api/admin/accounts",
        json={"expected_revision": rev, "account": _account()},
        headers=headers,
    ).json()
    patch = {
        "expected_revision": added["revision"],
        "account": {"smtp_port": 465, "smtp_mode": "ssl"},
    }
    assert client.patch("/api/admin/accounts/work", json=patch).status_code == 403
    changed = client.patch("/api/admin/accounts/work", json=patch, headers=headers)
    assert changed.status_code == 200
    deletion = {"expected_revision": changed.json()["revision"], "confirmation": "work"}
    assert client.request("DELETE", "/api/admin/accounts/work", json=deletion).status_code == 403
    assert (
        client.request("DELETE", "/api/admin/accounts/work", json=deletion, headers=headers).json()[
            "accounts"
        ]
        == []
    )


def test_non_expiring_key_http_requires_explicit_true_risk_acknowledgement(tmp_path: Path) -> None:
    client, headers = _client(_settings(tmp_path))
    rev = client.get("/api/admin/api-keys").json()["revision"]
    body = {"expected_revision": rev, "label": "agent", "scopes": ["mail:read"], "ttl_days": None}
    assert client.post("/api/admin/api-keys", json=body, headers=headers).status_code == 400
    assert (
        client.post(
            "/api/admin/api-keys", json={**body, "acknowledge_no_expiry": "true"}, headers=headers
        ).status_code
        == 422
    )
    issued = client.post(
        "/api/admin/api-keys", json={**body, "acknowledge_no_expiry": True}, headers=headers
    )
    assert issued.status_code == 200
    assert issued.json()["keys"][0]["expires_at"] is None
    assert issued.json()["token"] not in client.get("/api/admin/api-keys").text


def test_password_writes_are_encrypted_revision_checked_and_never_echoed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _settings(tmp_path)
    manager = AccountConfigManager(settings.account_config_file)
    added = manager.add(
        {**_account(), "auth_kind": "password"}, expected_revision=manager.snapshot()["revision"]
    )
    mail, headers = _client(settings)
    client = TestClient(
        approval_app(
            settings,
            approvals=ApprovalService(ApprovalRepository()),
            audit_recorder=lambda **kwargs: "",
        )
    )
    client.cookies.update(mail.cookies)
    body = {"expected_revision": added["revision"], "password": "test-private-app-password"}
    route = "/oauth/credentials/work/password"
    assert client.post(route, json=body).status_code == 403
    saved = client.post(route, json=body, headers=headers)
    assert saved.status_code == 200
    assert body["password"] not in saved.text
    assert body["password"] not in settings.credential_db.read_bytes().decode("latin1")
    assert body["password"] not in caplog.text
    status = client.get("/oauth/credentials")
    assert status.json()["accounts"][0]["credential_present"] is True
    assert body["password"] not in status.text
    store = CredentialStore.from_key_file(
        settings.credential_db, key_file=settings.credential_key_file, host_id=settings.host_id
    )
    assert store.get("microsoft:work")["password"] == body["password"]
    manager.set_enabled("work", enabled=False, expected_revision=added["revision"])
    assert (
        client.post(
            route, json={**body, "password": "should-not-save"}, headers=headers
        ).status_code
        == 409
    )
    assert store.get("microsoft:work")["password"] == body["password"]
    bad = client.post(
        route, json={**body, "password": {"private": body["password"]}}, headers=headers
    )
    assert bad.status_code == 422
    assert body["password"] not in bad.text
    client.cookies.clear()
    assert client.get("/oauth/credentials").status_code == 401
