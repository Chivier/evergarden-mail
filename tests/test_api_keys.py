from __future__ import annotations

import datetime as dt
import hashlib
import json
import stat
from pathlib import Path

import pytest

from evergarden.auth.api_keys import (
    MAX_API_KEYS,
    ApiKeyConflict,
    ApiKeyError,
    ApiKeyManager,
)
from evergarden.auth.models import InvalidToken
from evergarden.auth.policy import supported_scopes
from evergarden.auth.verifier import CompatibilityTokenVerifier

RESOURCE = "https://mail.test/mcp"
ISSUER = "https://auth.test"


def _manager(tmp_path: Path) -> ApiKeyManager:
    return ApiKeyManager(tmp_path / "keys" / "api_keys.json", resource=RESOURCE, mode="read-only")


def _issue(manager: ApiKeyManager, label: str, scopes: list[str], ttl_days: int = 90) -> dict:
    return manager.create(
        label=label,
        scopes=scopes,
        ttl_days=ttl_days,
        expected_revision=manager.snapshot()["revision"],
    )


def test_created_key_stores_only_a_hash_and_shows_plaintext_once(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    issued = _issue(manager, "Laptop", ["mail:read", "mail:metadata"])
    token = issued["token"]

    assert issued["client_id"] == "ui-laptop"
    raw = manager.path.read_text(encoding="utf-8")
    assert token not in raw
    assert hashlib.sha256(token.encode()).hexdigest() in raw

    # The plaintext is unreachable from every later read.
    listed = manager.snapshot()
    assert token not in json.dumps(listed)
    assert "sha256" not in json.dumps(listed)
    assert [key["client_id"] for key in listed["keys"]] == ["ui-laptop"]
    assert listed["keys"][0]["scopes"] == ["mail:metadata", "mail:read"]
    assert listed["keys"][0]["expired"] is False

    assert stat.S_IMODE(manager.path.stat().st_mode) == 0o600


@pytest.mark.asyncio
async def test_key_verifies_then_stops_verifying_once_revoked(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    issued = _issue(manager, "phone", ["mail:read"])
    verifier = CompatibilityTokenVerifier(
        manager.path, resource=RESOURCE, issuer=ISSUER, reload=True, optional=True
    )

    principal = await verifier.verify(issued["token"])
    assert principal.client_id == "ui-phone"
    assert principal.subject == "read-only:ui-phone"
    assert principal.scopes == {"mail:read"}

    manager.revoke("ui-phone", expected_revision=manager.snapshot()["revision"])
    with pytest.raises(InvalidToken):
        await verifier.verify(issued["token"])


def test_labels_collide_into_distinct_client_ids(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    first = _issue(manager, "My Laptop!", ["mail:read"])
    second = _issue(manager, "my  laptop", ["mail:read"])
    assert first["client_id"] == "ui-my-laptop"
    assert second["client_id"] == "ui-my-laptop-2"


def test_client_ids_always_carry_the_self_service_prefix(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    # A label that tries to impersonate an infrastructure client still lands
    # under the ui- namespace.
    assert _issue(manager, "mail-ui", ["mail:read"])["client_id"] == "ui-mail-ui"
    assert _issue(manager, "!!!", ["mail:read"])["client_id"] == "ui-key"


def test_stale_revision_and_unknown_key_are_refused(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    stale = manager.snapshot()["revision"]
    _issue(manager, "one", ["mail:read"])
    with pytest.raises(ApiKeyConflict):
        manager.create(label="two", scopes=["mail:read"], ttl_days=30, expected_revision=stale)
    with pytest.raises(ApiKeyConflict):
        manager.revoke("ui-one", expected_revision=stale)
    with pytest.raises(ApiKeyError, match="unknown"):
        manager.revoke("ui-absent", expected_revision=manager.snapshot()["revision"])


@pytest.mark.parametrize(
    ("label", "scopes", "ttl_days", "message"),
    [
        ("", ["mail:read"], 30, "1-48 characters"),
        ("x" * 49, ["mail:read"], 30, "1-48 characters"),
        ("ok", [], 30, "non-empty subset"),
        ("ok", ["mail:read", "mail:invented"], 30, "non-empty subset"),
        ("ok", "mail:read", 30, "non-empty subset"),
        ("ok", ["mail:read"], 0, "between 1 and 365"),
        ("ok", ["mail:read"], 366, "between 1 and 365"),
        ("ok", ["mail:read"], True, "whole number"),
    ],
)
def test_malformed_requests_are_refused(
    tmp_path: Path, label: object, scopes: object, ttl_days: object, message: str
) -> None:
    manager = _manager(tmp_path)
    with pytest.raises(ApiKeyError, match=message):
        manager.create(
            label=label,
            scopes=scopes,
            ttl_days=ttl_days,
            expected_revision=manager.snapshot()["revision"],
        )


def test_registry_size_is_bounded(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    for index in range(MAX_API_KEYS):
        _issue(manager, f"key{index}", ["mail:read"])
    with pytest.raises(ApiKeyError, match="revoke one first"):
        _issue(manager, "overflow", ["mail:read"])
    # The cap keeps the file loadable by the MCP verifier, which refuses more.
    CompatibilityTokenVerifier(manager.path, resource=RESOURCE, issuer=ISSUER)


def test_full_scope_grant_matches_what_the_service_serves(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    issued = _issue(manager, "full", supported_scopes())
    assert issued["keys"][0]["scopes"] == supported_scopes()


def test_expired_key_is_reported_but_not_silently_dropped(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    _issue(manager, "old", ["mail:read"], ttl_days=1)
    entries = json.loads(manager.path.read_text(encoding="utf-8"))
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
    entries["tokens"][0]["expires_at"] = past.isoformat(timespec="seconds")
    manager.path.write_text(json.dumps(entries), encoding="utf-8")
    manager.path.chmod(0o600)
    listed = manager.snapshot()
    assert listed["keys"][0]["expired"] is True


def test_key_issued_by_the_ui_reaches_a_running_mcp_service_without_a_restart(
    tmp_path: Path,
) -> None:
    from fastapi.testclient import TestClient

    from apps.mcp.main import create_app
    from evergarden.config import Settings

    registry = tmp_path / "keys" / "api_keys.json"
    # The MCP service starts before any key exists — exactly the deployment
    # order — so anything it accepts later came from a reload, not startup.
    verifier = CompatibilityTokenVerifier(
        registry, resource=RESOURCE, issuer=ISSUER, reload=True, optional=True
    )
    mcp = TestClient(
        create_app(
            Settings(mcp_resource=RESOURCE, oauth_issuer=ISSUER, compatibility_token_file=None),
            verifier=verifier,
            runtime=object(),
        )
    )

    def tools(token: str):
        return mcp.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={"jsonrpc": "2.0", "id": "1", "method": "tools/list"},
        )

    manager = ApiKeyManager(registry, resource=RESOURCE, mode="read-only")
    issued = _issue(manager, "laptop", ["mail:metadata", "mail:read"])

    listed = tools(issued["token"])
    assert listed.status_code == 200
    names = {tool["name"] for tool in listed.json()["result"]["tools"]}
    assert "search_mail" in names
    # The grant is honoured, not widened: no organize/send/delete tool appears.
    assert not names & {"archive_approved", "send_approved", "trash_approved"}

    manager.revoke(issued["client_id"], expected_revision=manager.snapshot()["revision"])
    assert tools(issued["token"]).status_code == 401


def test_registry_refuses_a_symlinked_path(tmp_path: Path) -> None:
    target = tmp_path / "real.json"
    target.write_text('{"tokens": []}', encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(target)
    manager = ApiKeyManager(link, resource=RESOURCE, mode="read-only")
    with pytest.raises(ApiKeyError, match="symlink"):
        manager.snapshot()
