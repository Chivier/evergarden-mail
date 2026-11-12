from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest

from evergarden.auth.credential_store import CredentialStore, generate_key
from evergarden.auth.maintenance import OAuthMaintenance


def setup_runtime(tmp_path):
    store = CredentialStore(tmp_path / "secrets" / "db", key=generate_key(), host_id="test")
    refreshes = []
    syncs = []
    clients = {}
    for account in ("work", "outlook"):
        record_id = f"microsoft:{account}"
        store.put(record_id, {"refresh_token": "refresh-secret"})
        clients[account] = SimpleNamespace(
            record_id=record_id,
            access_token=lambda *, refresh_margin_seconds, alias=account: refreshes.append(alias),
        )
    runtime = SimpleNamespace(
        store=store,
        oauth_clients=clients,
        sync_selected=lambda account, **_kwargs: syncs.append(account),
    )
    return runtime, refreshes, syncs


def put_flow(maintenance, *, state="test-flow", status="authorization_pending", **extra):
    maintenance.store.put(
        maintenance.coordinator._record_id(state),
        {
            "flow": "device_code",
            "state": state,
            "account": "work",
            "status": status,
            "expires_at": (maintenance.now() + dt.timedelta(minutes=15)).isoformat(),
            "interval": 5,
            "device_code": "private-device-code",
            **extra,
        },
    )


def test_background_finishes_device_login_and_syncs_without_browser(tmp_path, monkeypatch):
    runtime, refreshes, syncs = setup_runtime(tmp_path)
    maintenance = OAuthMaintenance(runtime)
    put_flow(maintenance)

    def complete(state):
        record_id = maintenance.coordinator._record_id(state)
        value = runtime.store.get(record_id)
        value.pop("device_code")
        runtime.store.put(record_id, {**value, "status": "authorized"})
        return {"status": "authorized"}

    monkeypatch.setattr(maintenance.coordinator, "poll_device", complete)
    assert maintenance.step()["synced_accounts"] == ["work"]
    assert syncs == ["work"]
    assert refreshes == ["work", "outlook"]
    assert maintenance.step()["synced_accounts"] == []
    restarted = OAuthMaintenance(runtime)
    assert restarted.step()["synced_accounts"] == []
    assert syncs == ["work"]
    stored = runtime.store.get(maintenance.coordinator._record_id("test-flow"))
    assert stored["sync_status"] == "synced"
    assert "device_code" not in stored


def test_refreshes_are_scheduled_and_accounts_fail_independently(tmp_path):
    runtime, refreshes, _syncs = setup_runtime(tmp_path)
    clock = [0.0]
    maintenance = OAuthMaintenance(runtime, monotonic=lambda: clock[0])

    def failed_refresh(**_kwargs):
        raise RuntimeError("provider unavailable")

    runtime.oauth_clients["work"].access_token = failed_refresh
    report = maintenance.step()
    assert report["checked_accounts"] == ["outlook"]
    assert report["failures"] == [{"account": "work", "error_class": "RuntimeError"}]
    clock[0] = 299
    assert maintenance.step()["checked_accounts"] == []
    clock[0] = 300
    assert maintenance.step()["checked_accounts"] == ["outlook"]
    assert refreshes == ["outlook", "outlook"]
    runtime.store.put(
        "microsoft:work",
        {
            "refresh_token": "refresh-secret",
            "oauth_failure": {"reauthorization_required": True},
        },
    )
    clock[0] = 600
    report = maintenance.step()
    assert report["authorization_required"] == ["work"]
    assert report["failures"] == []


def test_failed_post_authorization_sync_retries_after_restart(tmp_path):
    runtime, _refreshes, syncs = setup_runtime(tmp_path)
    clock = [dt.datetime.now(dt.UTC)]
    maintenance = OAuthMaintenance(runtime, now=lambda: clock[0])
    put_flow(maintenance, status="authorized")

    def failed_sync(_account, **_kwargs):
        raise TimeoutError("mail server unavailable")

    runtime.sync_selected = failed_sync
    assert maintenance.step()["failures"][0]["error_class"] == "TimeoutError"
    restarted = OAuthMaintenance(runtime, now=lambda: clock[0])
    runtime.sync_selected = lambda account, **_kwargs: syncs.append(account)
    assert restarted.step()["synced_accounts"] == []
    clock[0] += dt.timedelta(seconds=300)
    assert restarted.step()["synced_accounts"] == ["work"]
    assert syncs == ["work"]


def test_background_ignores_expired_flows_and_uses_latest_request(tmp_path, monkeypatch):
    runtime, _refreshes, _syncs = setup_runtime(tmp_path)
    maintenance = OAuthMaintenance(runtime)
    put_flow(
        maintenance,
        state="expired",
        expires_at=(maintenance.now() - dt.timedelta(seconds=1)).isoformat(),
    )
    assert maintenance._flows() == []
    put_flow(
        maintenance,
        state="first",
        expires_at=(maintenance.now() + dt.timedelta(minutes=5)).isoformat(),
    )
    put_flow(maintenance, state="second")
    polled = []

    def pending(state):
        polled.append(state)
        return {"status": "authorization_pending"}

    monkeypatch.setattr(maintenance.coordinator, "poll_device", pending)
    maintenance.step()
    assert polled == ["second"]


def test_maintenance_cli_rejects_read_only_owner(monkeypatch):
    from apps.worker import oauth_maintenance

    monkeypatch.setattr("sys.argv", ["oauth-maintenance", "--once"])
    monkeypatch.setattr(
        oauth_maintenance, "get_settings", lambda: SimpleNamespace(mode="read-only")
    )
    with pytest.raises(RuntimeError, match="active production"):
        oauth_maintenance.main()
