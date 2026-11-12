from __future__ import annotations

import datetime as dt
from pathlib import Path

import httpx
import pytest

from evergarden.auth.credential_store import CredentialStore, generate_key
from evergarden.auth.oauth_coordinator import OAuthCoordinator, OAuthStateError
from evergarden.auth.provider_oauth import (
    MICROSOFT_CLIENT_ID_PLACEHOLDER,
    MicrosoftConfigurationError,
    MicrosoftOAuthClient,
    OAuthConfigurationError,
    OAuthRegistration,
    microsoft_registration,
)

CLIENT_ID = "11111111-2222-3333-4444-555555555555"


class DeviceHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, *, data, timeout):
        self.calls.append((url, data))
        return self.responses.pop(0)


def device_response(**changes):
    return httpx.Response(
        200,
        json={
            "device_code": "private-device-secret",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://login.microsoft.com/device",
            "expires_in": 900,
            "interval": 5,
            **changes,
        },
    )


def coordinator(tmp_path, http, clock):
    store = CredentialStore(tmp_path / "secrets" / "db", key=generate_key(), host_id="test")
    client = MicrosoftOAuthClient(
        store=store,
        record_id="microsoft:work",
        registration=OAuthRegistration(client_id=CLIENT_ID, flow="device_code"),
        http=http,
    )
    return OAuthCoordinator(store=store, clients={"work": client}, now=lambda: clock[0])


def test_device_login_throttles_and_persists_credentials_once(tmp_path: Path, monkeypatch):
    clock = [dt.datetime.now(dt.UTC)]
    monkeypatch.setattr("evergarden.auth.provider_oauth._now", lambda: clock[0])
    http = DeviceHttp(
        [
            device_response(),
            httpx.Response(400, json={"error": "authorization_pending"}),
            httpx.Response(400, json={"error": "slow_down"}),
            httpx.Response(
                200,
                json={
                    "access_token": "new-access-secret",
                    "refresh_token": "new-refresh-secret",
                    "expires_in": 3600,
                },
            ),
        ]
    )
    oauth = coordinator(tmp_path, http, clock)
    oauth.store.put(
        "microsoft:work",
        {
            "refresh_token": "old-refresh",
            "oauth_failure": {"reauthorization_required": True},
        },
    )
    started = oauth.start("work")
    assert started["flow"] == "device_code"
    assert "device_code" not in started
    assert "private-device-secret" not in str(started)
    assert b"private-device-secret" not in oauth.store.path.read_bytes()
    assert "redirect_uri" not in http.calls[0][1]
    flow_id = started["flow_id"]
    assert oauth.poll_device(flow_id)["status"] == "authorization_pending"
    assert len(http.calls) == 1
    clock[0] += dt.timedelta(seconds=5)
    assert oauth.poll_device(flow_id)["status"] == "authorization_pending"
    clock[0] += dt.timedelta(seconds=5)
    assert oauth.poll_device(flow_id) == {
        "account": "work",
        "status": "slow_down",
        "interval": 10,
    }
    clock[0] += dt.timedelta(seconds=9)
    assert oauth.poll_device(flow_id)["status"] == "authorization_pending"
    assert len(http.calls) == 3
    clock[0] += dt.timedelta(seconds=1)
    assert oauth.poll_device(flow_id)["status"] == "authorized"
    assert oauth.poll_device(flow_id)["status"] == "authorized"
    assert len(http.calls) == 4
    record = oauth.store.get("microsoft:work")
    assert record["refresh_token"] == "new-refresh-secret"
    assert "oauth_failure" not in record
    assert "device_code" not in oauth.store.get(oauth._record_id(flow_id))
    assert http.calls[-1][1]["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"


@pytest.mark.parametrize("status", ["authorization_declined", "expired_token"])
def test_device_terminal_response_cannot_be_replayed(tmp_path: Path, monkeypatch, status):
    clock = [dt.datetime.now(dt.UTC)]
    monkeypatch.setattr("evergarden.auth.provider_oauth._now", lambda: clock[0])
    http = DeviceHttp([device_response(), httpx.Response(400, json={"error": status})])
    oauth = coordinator(tmp_path, http, clock)
    started = oauth.start("work")
    clock[0] += dt.timedelta(seconds=5)
    assert oauth.poll_device(started["flow_id"])["status"] == status
    with pytest.raises(OAuthStateError, match="declined or expired"):
        oauth.poll_device(started["flow_id"])
    assert "device_code" not in oauth.store.get(oauth._record_id(started["flow_id"]))
    assert len(http.calls) == 2


def test_device_state_is_bound_expiring_and_separate_from_pkce(tmp_path: Path, monkeypatch):
    clock = [dt.datetime.now(dt.UTC)]
    monkeypatch.setattr("evergarden.auth.provider_oauth._now", lambda: clock[0])
    http = DeviceHttp([device_response()])
    oauth = coordinator(tmp_path, http, clock)
    started = oauth.start("work")
    with pytest.raises(OAuthStateError, match="unknown"):
        oauth.poll_device("unknown-state")
    with pytest.raises(OAuthStateError, match="invalid"):
        oauth.callback(state=started["flow_id"], code="wrong-flow-code")
    clock[0] += dt.timedelta(seconds=901)
    with pytest.raises(OAuthStateError, match="expired"):
        oauth.poll_device(started["flow_id"])
    assert len(http.calls) == 1


def test_concurrent_device_poll_does_not_exchange_twice(tmp_path: Path, monkeypatch):
    clock = [dt.datetime.now(dt.UTC)]
    monkeypatch.setattr("evergarden.auth.provider_oauth._now", lambda: clock[0])
    oauth = coordinator(tmp_path, DeviceHttp([device_response()]), clock)
    started = oauth.start("work")
    clock[0] += dt.timedelta(seconds=5)
    polls = []

    def poll(_device_code):
        polls.append(oauth.poll_device(started["flow_id"]))
        return "authorization_pending"

    monkeypatch.setattr(oauth.clients["work"], "poll_device_authorization", poll)
    assert oauth.poll_device(started["flow_id"])["status"] == "authorization_pending"
    assert polls == [{"account": "work", "status": "authorization_pending", "interval": 5}]


@pytest.mark.parametrize(
    "changes",
    [
        {"verification_uri": "https://login.microsoft.com.attacker.test/device"},
        {"device_code": ""},
        {"expires_in": 0},
        {"interval": 0},
    ],
)
def test_device_start_rejects_malformed_provider_responses(tmp_path: Path, changes):
    oauth = coordinator(
        tmp_path, DeviceHttp([device_response(**changes)]), [dt.datetime.now(dt.UTC)]
    )
    with pytest.raises(RuntimeError, match="malformed"):
        oauth.start("work")


def test_flow_is_an_explicit_setting_not_inferred_from_the_client_id(tmp_path: Path):
    store = CredentialStore(tmp_path / "db", key=generate_key(), host_id="test")

    def client(**registration):
        return MicrosoftOAuthClient(
            store=store,
            record_id="microsoft:work",
            registration=OAuthRegistration(client_id=CLIENT_ID, **registration),
            http=DeviceHttp([]),
        )

    default = client()
    assert default.flow == "authorization_code"
    assert not default.uses_device_authorization
    assert default.configured and default.app_name == ""
    device = client(flow="device_code", app_name="Example Mail")
    assert device.uses_device_authorization and device.app_name == "Example Mail"
    with pytest.raises(ValueError, match="flow must be one of"):
        OAuthRegistration(client_id=CLIENT_ID, flow="implicit")


@pytest.mark.parametrize("flow", ["authorization_code", "device_code"])
def test_placeholder_client_id_asks_for_an_own_entra_app(tmp_path: Path, flow):
    store = CredentialStore(tmp_path / "db", key=generate_key(), host_id="test")
    http = DeviceHttp([])
    client = MicrosoftOAuthClient(
        store=store,
        record_id="microsoft:work",
        registration=OAuthRegistration(client_id=MICROSOFT_CLIENT_ID_PLACEHOLDER, flow=flow),
        http=http,
    )
    assert client.configured is False
    oauth = OAuthCoordinator(store=store, clients={"work": client})
    with pytest.raises(MicrosoftConfigurationError, match="register your own Microsoft Entra app"):
        oauth.start("work")
    assert http.calls == []
    assert issubclass(MicrosoftConfigurationError, OAuthConfigurationError)


def test_registration_follows_settings():
    from evergarden.config import Settings

    settings = Settings(
        microsoft_oauth_client_id=CLIENT_ID,
        microsoft_oauth_flow="device_code",
        microsoft_oauth_app_name="Example Mail",
    )
    registration = microsoft_registration(settings)
    assert registration.flow == "device_code"
    assert registration.app_name == "Example Mail"
    assert registration.client_id == CLIENT_ID
    defaults = microsoft_registration(Settings())
    assert defaults.flow == "authorization_code"
    assert defaults.client_id == MICROSOFT_CLIENT_ID_PLACEHOLDER
    assert not defaults.configured
