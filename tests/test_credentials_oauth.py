from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

import httpx
import pytest

from evergarden.auth.credential_store import (
    CredentialDecryptionError,
    CredentialNotFound,
    CredentialStore,
    CredentialStoreError,
    decode_key,
    encode_key,
    generate_key,
    read_key_file,
)
from evergarden.auth.oauth_coordinator import OAuthCoordinator, OAuthStateError
from evergarden.auth.provider_oauth import (
    MICROSOFT_SCOPES,
    AuthorizationRequest,
    MicrosoftOAuthClient,
    OAuthRegistration,
    OAuthTokenRequestError,
)


class FakeHttp:
    def __init__(self, responses: list[httpx.Response]):
        self.responses = responses
        self.calls: list[dict] = []

    def post(self, url: str, *, data, timeout: float) -> httpx.Response:
        self.calls.append({"url": url, "data": dict(data), "timeout": timeout})
        return self.responses.pop(0)


def test_credential_store_host_binding_tamper_restart_and_rekey(tmp_path: Path) -> None:
    key = generate_key()
    path = tmp_path / "secrets" / "credentials.db"
    store = CredentialStore(path, key=key, host_id="host-a")
    assert store.put("microsoft:work", {"refresh_token": "never-plaintext"}) == 1
    assert store.get("microsoft:work")["refresh_token"] == "never-plaintext"
    assert b"never-plaintext" not in path.read_bytes()
    assert path.stat().st_mode & 0o077 == 0
    assert path.parent.stat().st_mode & 0o077 == 0

    restarted = CredentialStore(path, key=key, host_id="host-a")
    assert restarted.get("microsoft:work")["refresh_token"] == "never-plaintext"
    with pytest.raises(CredentialDecryptionError):
        CredentialStore(path, key=key, host_id="host-b").get("microsoft:work")
    with pytest.raises(CredentialDecryptionError):
        CredentialStore(path, key=generate_key(), host_id="host-a").get("microsoft:work")
    with pytest.raises(CredentialNotFound):
        store.get("missing")

    replacement = generate_key()
    store.rekey(replacement)
    assert store.get("microsoft:work")["refresh_token"] == "never-plaintext"
    with pytest.raises(CredentialDecryptionError):
        CredentialStore(path, key=key, host_id="host-a").get("microsoft:work")
    assert CredentialStore(path, key=replacement, host_id="host-a").metadata()[0]["version"] == 2


def test_key_encoding_permissions_and_compare_and_swap(tmp_path: Path) -> None:
    key = generate_key()
    assert decode_key(encode_key(key)) == key
    with pytest.raises(CredentialStoreError):
        decode_key("bad")
    key_file = tmp_path / "key"
    key_file.write_text(encode_key(key))
    key_file.chmod(0o644)
    with pytest.raises(CredentialStoreError):
        read_key_file(key_file)
    key_file.chmod(0o600)
    assert read_key_file(key_file) == key

    key_target = tmp_path / "key-target"
    key_target.write_text(encode_key(key))
    key_target.chmod(0o600)
    key_link = tmp_path / "key-link"
    key_link.symlink_to(key_target)
    with pytest.raises(CredentialStoreError, match="non-symlink regular file"):
        read_key_file(key_link)

    key_directory = tmp_path / "key-directory"
    key_directory.mkdir(mode=0o700)
    with pytest.raises(CredentialStoreError, match="regular file"):
        read_key_file(key_directory)

    store = CredentialStore(tmp_path / "store" / "db.sqlite", key=key, host_id="host-a")
    version = store.put("record", {"value": 1})
    assert store.put_if_version("record", expected_version=version, value={"value": 2}) == 2
    with pytest.raises(CredentialStoreError):
        store.put_if_version("record", expected_version=version, value={"value": 3})
    assert store.get("record") == {"value": 2}


def test_microsoft_refresh_persists_and_does_not_log_tokens(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    key = generate_key()
    store = CredentialStore(tmp_path / "secrets" / "db.sqlite", key=key, host_id="host-a")
    store.put(
        "microsoft:outlook",
        {
            "access_token": "expired-access",
            "refresh_token": "old-refresh",
            "expires_at": "2020-01-01T00:00:00+00:00",
        },
    )
    response = httpx.Response(
        200,
        json={
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600,
            "scope": " ".join(MICROSOFT_SCOPES),
        },
    )
    fake = FakeHttp([response])
    client = MicrosoftOAuthClient(
        store=store,
        record_id="microsoft:outlook",
        registration=OAuthRegistration(client_id="public-client"),
        http=fake,
    )
    with caplog.at_level(logging.INFO):
        assert client.access_token() == "new-access-token"
    assert fake.calls[0]["data"]["grant_type"] == "refresh_token"
    assert store.get("microsoft:outlook")["refresh_token"] == "rotated-refresh-token"
    assert "new-access-token" not in caplog.text
    assert "rotated-refresh-token" not in caplog.text

    restarted = MicrosoftOAuthClient(
        store=CredentialStore(store.path, key=key, host_id="host-a"),
        record_id="microsoft:outlook",
        registration=OAuthRegistration(client_id="public-client"),
        http=FakeHttp([]),
    )
    assert restarted.access_token() == "new-access-token"


def test_microsoft_force_refresh_replaces_nominally_valid_token(tmp_path: Path) -> None:
    store = CredentialStore(
        tmp_path / "secrets" / "db.sqlite", key=generate_key(), host_id="host-a"
    )
    store.put(
        "microsoft:outlook",
        {
            "access_token": "provider-rejected",
            "refresh_token": "refresh-token",
            "expires_at": (dt.datetime.now(dt.UTC) + dt.timedelta(hours=2)).isoformat(),
        },
    )
    fake = FakeHttp(
        [httpx.Response(200, json={"access_token": "forced-fresh", "expires_in": 3600})]
    )
    client = MicrosoftOAuthClient(
        store=store,
        record_id="microsoft:outlook",
        registration=OAuthRegistration(client_id="public-client"),
        http=fake,
    )
    assert client.access_token(force_refresh=True) == "forced-fresh"
    assert len(fake.calls) == 1


def test_oauth_error_body_is_not_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    store = CredentialStore(tmp_path / "s" / "db", key=generate_key(), host_id="host-a")
    store.put("microsoft:x", {"refresh_token": "refresh-secret"})
    client = MicrosoftOAuthClient(
        store=store,
        record_id="microsoft:x",
        registration=OAuthRegistration(client_id="public"),
        http=FakeHttp([httpx.Response(400, json={"error_description": "token-secret"})]),
    )
    with caplog.at_level(logging.WARNING), pytest.raises(RuntimeError):
        client.refresh()
    assert "token-secret" not in caplog.text
    assert "refresh-secret" not in caplog.text


def test_expired_grant_records_safe_diagnostics_and_clears_after_success(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = CredentialStore(tmp_path / "s" / "db", key=generate_key(), host_id="host-a")
    prior = {"refresh_token": "refresh-secret", "access_token": "access-secret"}
    store.put("microsoft:work", prior)
    client = MicrosoftOAuthClient(
        store=store,
        record_id="microsoft:work",
        registration=OAuthRegistration(client_id="public"),
        http=FakeHttp(
            [
                httpx.Response(
                    400,
                    json={
                        "error": "invalid_grant",
                        "error_codes": [70043],
                        "error_description": "private user@example.test refresh-secret",
                    },
                ),
                httpx.Response(200, json={"access_token": "fresh-access", "expires_in": 3600}),
            ]
        ),
    )
    with caplog.at_level(logging.WARNING), pytest.raises(OAuthTokenRequestError) as caught:
        client.refresh()
    assert caught.value.reauthorization_required is True
    assert "AADSTS70043" in str(caught.value)
    assert "interactive reauthorization required" in str(caught.value)
    assert "private" not in caplog.text
    assert "refresh-secret" not in caplog.text
    assert "user@example.test" not in str(caught.value)
    failed = store.get("microsoft:work")
    assert failed["refresh_token"] == prior["refresh_token"]
    assert failed["access_token"] == prior["access_token"]
    assert failed["oauth_failure"] == {
        "error": "invalid_grant",
        "error_codes": [70043],
        "reauthorization_required": True,
    }
    client.refresh()
    restored = store.get("microsoft:work")
    assert "oauth_failure" not in restored
    assert restored["access_token"] == "fresh-access"


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "secret-string", "error_codes": [True, "secret", 70043, -1, 10_000_000]},
        {"error": ["secret"], "error_codes": "secret"},
        ["secret"],
    ],
)
def test_oauth_diagnostics_only_include_known_codes(tmp_path: Path, payload) -> None:
    store = CredentialStore(tmp_path / "s" / "db", key=generate_key(), host_id="host-a")
    store.put("microsoft:x", {"refresh_token": "refresh-secret"})
    client = MicrosoftOAuthClient(
        store=store,
        record_id="microsoft:x",
        registration=OAuthRegistration(client_id="public"),
        http=FakeHttp([httpx.Response(400, json=payload)]),
    )
    with pytest.raises(OAuthTokenRequestError) as caught:
        client.refresh()
    assert "secret" not in str(caught.value)
    assert caught.value.error == "token_request_failed"
    assert caught.value.reauthorization_required is False


class CoordinatorClient:
    def __init__(self, now: dt.datetime, state: str = "state-value"):
        self.now = now
        self.state = state
        self.exchanges: list[tuple[str, str]] = []

    def build_authorization_request(self) -> AuthorizationRequest:
        return AuthorizationRequest("https://login.test/auth", self.state, "verifier", self.now)

    def exchange_code(self, *, code: str, code_verifier: str) -> dict:
        self.exchanges.append((code, code_verifier))
        return {"access_token": "not-logged"}


def test_oauth_coordinator_state_expiry_and_one_shot(
    tmp_path: Path, fixed_now: dt.datetime
) -> None:
    store = CredentialStore(tmp_path / "s" / "db", key=generate_key(), host_id="host-a")
    client = CoordinatorClient(fixed_now + dt.timedelta(minutes=5))
    coordinator = OAuthCoordinator(store=store, clients={"work": client}, now=lambda: fixed_now)
    started = coordinator.start("work")
    assert started["authorization_url"].startswith("https://")
    assert coordinator.callback(state=started["state"], code="one-time") == {
        "account": "work",
        "status": "authorized",
    }
    assert client.exchanges == [("one-time", "verifier")]
    with pytest.raises(OAuthStateError):
        coordinator.callback(state=started["state"], code="replay")
    with pytest.raises(OAuthStateError):
        coordinator.start("unknown")

    expired_client = CoordinatorClient(fixed_now - dt.timedelta(seconds=1))
    expired = OAuthCoordinator(
        store=store, clients={"outlook": expired_client}, now=lambda: fixed_now
    )
    expired_state = expired.start("outlook")
    with pytest.raises(OAuthStateError, match="expired"):
        expired.callback(state=expired_state["state"], code="code")


def test_pending_oauth_state_is_pruned_once_the_flow_cannot_complete(
    tmp_path: Path, fixed_now: dt.datetime
) -> None:
    store = CredentialStore(tmp_path / "s" / "db", key=generate_key(), host_id="host-a")
    client = CoordinatorClient(fixed_now + dt.timedelta(minutes=5))
    now = fixed_now

    def clock() -> dt.datetime:
        return now

    other = CoordinatorClient(fixed_now + dt.timedelta(minutes=5), state="other-state")
    coordinator = OAuthCoordinator(
        store=store, clients={"work": client, "outlook": other}, now=clock
    )
    consumed = coordinator.start("work")
    coordinator.callback(state=consumed["state"], code="one-time")
    abandoned = coordinator.start("outlook")

    def pending_ids() -> list[str]:
        return [
            item["record_id"]
            for item in store.metadata()
            if item["record_id"].startswith("oauth-pending:")
        ]

    # Inside the retention window nothing is touched — including the record
    # that was just consumed and the flow still waiting for the user.
    assert coordinator.prune_pending() == 0
    assert len(pending_ids()) == 2

    # Once the flows' expiry lies past the retention window both are dead
    # weight: the consumed record and the abandoned one are deleted.
    now = fixed_now + dt.timedelta(days=1, minutes=6)
    assert coordinator.prune_pending() == 2
    assert pending_ids() == []
    with pytest.raises(OAuthStateError):
        coordinator.callback(state=abandoned["state"], code="late")

    # A record that can no longer be decrypted is pruned by file age.
    stale = coordinator.start("work")
    record_id = coordinator._record_id(str(stale["state"]))
    CredentialStore(tmp_path / "s" / "db", key=generate_key(), host_id="host-a")
    other_key_store = CredentialStore(tmp_path / "s" / "db", key=generate_key(), host_id="host-a")
    # The store stamps updated_at with wall-clock time, so the unreadable
    # branch needs a clock past that, not the fixture's frozen 2026-08-17.
    now = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)
    unreadable = OAuthCoordinator(store=other_key_store, clients={"work": client}, now=clock)
    assert unreadable.prune_pending(retain=dt.timedelta(days=1)) == 1
    assert record_id not in [item["record_id"] for item in other_key_store.metadata()]


def test_credential_store_rejects_symlink_paths(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    target.write_bytes(b"")
    link = tmp_path / "credentials.db"
    link.symlink_to(target)
    with pytest.raises(CredentialStoreError, match="symlink"):
        CredentialStore(link, key=generate_key(), host_id="host-a")


def test_credential_store_rejects_unsafe_database_files(tmp_path: Path) -> None:
    key = generate_key()
    path = tmp_path / "private" / "credentials.db"
    CredentialStore(path, key=key, host_id="host-a")
    path.chmod(0o644)
    with pytest.raises(CredentialStoreError, match="no group/world permissions"):
        CredentialStore(path, key=key, host_id="host-a")

    path.chmod(0o600)
    sidecar_target = tmp_path / "sidecar-target"
    sidecar_target.write_bytes(b"")
    sidecar = path.with_name(path.name + "-wal")
    sidecar.symlink_to(sidecar_target)
    with pytest.raises(CredentialStoreError, match=r"sidecar.*symlink"):
        CredentialStore(path, key=key, host_id="host-a")


def test_credential_store_tolerates_vanishing_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A concurrent WAL checkpoint can remove -wal/-shm between the existence
    # check and the stat/chmod; the 2026-10-24 oauth-watchdog run failed with
    # FileNotFoundError on credentials.db-shm exactly this way.
    key = generate_key()
    path = tmp_path / "secrets" / "credentials.db"
    store = CredentialStore(path, key=key, host_id="host-a")

    real_lstat = Path.lstat
    real_chmod = Path.chmod

    def vanishing_lstat(self: Path, *args, **kwargs):
        if self.name.endswith(("-wal", "-shm")):
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_lstat(self, *args, **kwargs)

    def vanishing_chmod(self: Path, *args, **kwargs):
        if self.name.endswith(("-wal", "-shm")):
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_chmod(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", vanishing_lstat)
    monkeypatch.setattr(Path, "chmod", vanishing_chmod)
    assert store.put("microsoft:work", {"refresh_token": "still-works"}) == 1
    assert store.get("microsoft:work")["refresh_token"] == "still-works"


def test_credential_store_rejects_symlink_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(CredentialStoreError, match=r"directory.*symlink"):
        CredentialStore(
            linked_parent / "credentials.db",
            key=generate_key(),
            host_id="host-a",
        )
