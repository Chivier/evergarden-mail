from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from evergarden.auth.discovery import (
    authorization_server_metadata_url,
    protected_resource_metadata,
    protected_resource_metadata_url,
)
from evergarden.auth.models import InsufficientScope, InvalidToken, Principal
from evergarden.auth.policy import FORBIDDEN_TOOL_NAMES, require_scope, visible_tools
from evergarden.auth.verifier import (
    CompatibilityTokenVerifier,
    CompositeVerifier,
    IntrospectionVerifier,
    JwtVerifier,
)


def _jwt_fixture(*, audience: str = "https://mail.test/mcp", issuer: str = "https://auth.test"):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": "key-1", "use": "sig", "alg": "RS256"})
    now = dt.datetime.now(dt.UTC)
    claims = {
        "sub": "user-1",
        "client_id": "codex",
        "scope": "mail:read mail:draft",
        "aud": audience,
        "iss": issuer,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=5)).timestamp()),
    }
    return private, {"keys": [jwk]}, claims


@pytest.mark.asyncio
async def test_jwt_verifier_enforces_signature_issuer_audience_and_expiry() -> None:
    private, jwks, claims = _jwt_fixture()
    verifier = JwtVerifier(issuer="https://auth.test", resource="https://mail.test/mcp", jwks=jwks)
    token = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "key-1"})
    principal = await verifier.verify(token)
    assert principal.client_id == "codex"
    assert principal.scopes == {"mail:read", "mail:draft"}

    for update in (
        {"aud": "https://other.test/mcp"},
        {"iss": "https://wrong.test"},
        {"exp": int((dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)).timestamp())},
    ):
        bad = jwt.encode({**claims, **update}, private, algorithm="RS256", headers={"kid": "key-1"})
        with pytest.raises(InvalidToken):
            await verifier.verify(bad)
    with pytest.raises(InvalidToken):
        await verifier.verify("not-a-jwt")


class AsyncHttp:
    def __init__(self, response: httpx.Response | Exception):
        self.response = response
        self.calls: list[dict] = []

    async def post(self, endpoint: str, **kwargs):
        self.calls.append({"endpoint": endpoint, **kwargs})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.mark.asyncio
async def test_introspection_verifier_and_fail_closed_transport() -> None:
    now = dt.datetime.now(dt.UTC)
    http = AsyncHttp(
        httpx.Response(
            200,
            json={
                "active": True,
                "sub": "user",
                "client_id": "agent",
                "scope": ["mail:read"],
                "aud": ["https://mail.test/mcp"],
                "iss": "https://auth.test",
                "exp": int((now + dt.timedelta(minutes=5)).timestamp()),
            },
        )
    )
    verifier = IntrospectionVerifier(
        endpoint="https://auth.test/introspect",
        client_id="resource-server",
        client_secret="not-logged",
        issuer="https://auth.test",
        resource="https://mail.test/mcp",
        http=http,
    )
    assert (await verifier.verify("opaque")).client_id == "agent"
    assert http.calls[0]["data"]["token"] == "opaque"

    inactive = IntrospectionVerifier(
        endpoint="https://auth.test/introspect",
        client_id="id",
        client_secret="secret",
        issuer="https://auth.test",
        resource="https://mail.test/mcp",
        http=AsyncHttp(httpx.Response(200, json={"active": False})),
    )
    with pytest.raises(InvalidToken):
        await inactive.verify("opaque")
    unavailable = IntrospectionVerifier(
        endpoint="https://auth.test/introspect",
        client_id="id",
        client_secret="secret",
        issuer="https://auth.test",
        resource="https://mail.test/mcp",
        http=AsyncHttp(httpx.ConnectError("down")),
    )
    with pytest.raises(InvalidToken):
        await unavailable.verify("opaque")

    malformed = IntrospectionVerifier(
        endpoint="https://auth.test/introspect",
        client_id="id",
        client_secret="secret",
        issuer="https://auth.test",
        resource="https://mail.test/mcp",
        http=AsyncHttp(
            httpx.Response(
                200,
                content=b"not-json",
                headers={"content-type": "application/json"},
            )
        ),
    )
    with pytest.raises(InvalidToken, match="response is malformed"):
        await malformed.verify("opaque")


@pytest.mark.asyncio
async def test_hash_only_compatibility_tokens_are_client_scoped_and_expire(
    tmp_path: Path,
) -> None:
    raw = "c" * 64
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {
                "tokens": [
                    {
                        "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                        "client_id": "claude",
                        "subject": "read-only:claude",
                        "audience": ["https://mail.test/mcp"],
                        "scopes": ["mail:read", "mail:draft"],
                        "expires_at": (dt.datetime.now(dt.UTC) + dt.timedelta(days=1)).isoformat(),
                    }
                ]
            }
        )
    )
    path.chmod(0o600)
    verifier = CompatibilityTokenVerifier(
        path, resource="https://mail.test/mcp", issuer="https://auth.test"
    )
    principal = await verifier.verify(raw)
    assert principal.client_id == "claude"
    assert principal.scopes == {"mail:read", "mail:draft"}
    assert raw not in path.read_text()
    with pytest.raises(InvalidToken):
        await verifier.verify("wrong")

    path.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        CompatibilityTokenVerifier(path, resource="x", issuer="y")


def _registry(path: Path, tokens: list[str], *, days: int = 1) -> None:
    expires = (dt.datetime.now(dt.UTC) + dt.timedelta(days=days)).isoformat()
    path.write_text(
        json.dumps(
            {
                "tokens": [
                    {
                        "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                        "client_id": f"ui-{index}",
                        "subject": f"read-only:ui-{index}",
                        "audience": ["https://mail.test/mcp"],
                        "scopes": ["mail:read"],
                        "expires_at": expires,
                    }
                    for index, raw in enumerate(tokens)
                ]
            }
        )
    )
    path.chmod(0o600)


@pytest.mark.asyncio
async def test_reloading_registry_tracks_issuance_and_revocation(tmp_path: Path) -> None:
    path = tmp_path / "api_keys.json"
    verifier = CompatibilityTokenVerifier(
        path,
        resource="https://mail.test/mcp",
        issuer="https://auth.test",
        reload=True,
        optional=True,
    )
    first, second = "f" * 40, "s" * 40
    # A registry that does not exist yet is an empty one, not a startup failure.
    with pytest.raises(InvalidToken):
        await verifier.verify(first)

    _registry(path, [first])
    assert (await verifier.verify(first)).client_id == "ui-0"

    _registry(path, [first, second])
    assert (await verifier.verify(second)).client_id == "ui-1"

    _registry(path, [second])
    with pytest.raises(InvalidToken):
        await verifier.verify(first)

    path.unlink()
    with pytest.raises(InvalidToken):
        await verifier.verify(second)


@pytest.mark.asyncio
async def test_expired_registry_entry_is_rejected_at_verify_time(tmp_path: Path) -> None:
    raw = "e" * 40
    path = tmp_path / "api_keys.json"
    _registry(path, [raw], days=-1)
    # Loading tolerates an already-expired entry (it is below the TTL horizon);
    # verification must still reject it.
    verifier = CompatibilityTokenVerifier(
        path, resource="https://mail.test/mcp", issuer="https://auth.test"
    )
    with pytest.raises(InvalidToken, match="expired"):
        await verifier.verify(raw)


@pytest.mark.asyncio
async def test_corrupted_optional_registry_does_not_abort_startup(tmp_path: Path) -> None:
    path = tmp_path / "api_keys.json"
    path.write_text("{ not json")
    path.chmod(0o600)
    # Init must match _maybe_reload: fail soft for the optional registry so a
    # damaged self-service key file cannot take the whole MCP app down.
    verifier = CompatibilityTokenVerifier(
        path,
        resource="https://mail.test/mcp",
        issuer="https://auth.test",
        reload=True,
        optional=True,
    )
    assert verifier.entries == []
    with pytest.raises(InvalidToken):
        await verifier.verify("x" * 40)
    # The required registry still fails startup loudly.
    with pytest.raises(ValueError):
        CompatibilityTokenVerifier(path, resource="x", issuer="y")

    # Once the file is repaired, reload picks the entries back up.
    raw = "g" * 40
    _registry(path, [raw])
    assert (await verifier.verify(raw)).client_id == "ui-0"


@pytest.mark.asyncio
async def test_corrupted_reload_fails_closed_instead_of_reusing_old_entries(
    tmp_path: Path,
) -> None:
    path = tmp_path / "api_keys.json"
    raw = "r" * 40
    _registry(path, [raw])
    verifier = CompatibilityTokenVerifier(
        path,
        resource="https://mail.test/mcp",
        issuer="https://auth.test",
        reload=True,
        optional=True,
    )
    assert (await verifier.verify(raw)).client_id == "ui-0"

    # A revoked key must not come back to life because the file was damaged.
    path.write_text("{ not json")
    path.chmod(0o600)
    with pytest.raises(InvalidToken):
        await verifier.verify(raw)
    assert verifier.entries == []


def test_missing_registry_still_fails_startup_when_it_is_required(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing"):
        CompatibilityTokenVerifier(tmp_path / "absent.json", resource="x", issuer="y")


def test_registry_ceilings_bound_entry_count_and_expiry_horizon(tmp_path: Path) -> None:
    crowded = tmp_path / "crowded.json"
    _registry(crowded, [f"token-{index}-{'x' * 32}" for index in range(33)])
    with pytest.raises(ValueError, match="too many entries"):
        CompatibilityTokenVerifier(crowded, resource="x", issuer="y")

    distant = tmp_path / "distant.json"
    _registry(distant, ["d" * 40], days=401)
    with pytest.raises(ValueError, match="horizon"):
        CompatibilityTokenVerifier(distant, resource="x", issuer="y")


@pytest.mark.asyncio
async def test_composite_verifier_tries_isolated_verifiers() -> None:
    principal = Principal.build(
        subject="u", client_id="codex", scopes="mail:read", audience="resource", issuer="i"
    )

    class Reject:
        async def verify(self, token: str):
            raise InvalidToken("no")

    class Accept:
        async def verify(self, token: str):
            return principal

    assert await CompositeVerifier([Reject(), Accept()]).verify("token") == principal
    with pytest.raises(InvalidToken):
        await CompositeVerifier([Reject()]).verify("token")
    with pytest.raises(ValueError):
        CompositeVerifier([])


def test_rfc9728_discovery_and_scope_visibility() -> None:
    resource = "https://mail.test/mcp"
    assert (
        protected_resource_metadata_url(resource)
        == "https://mail.test/.well-known/oauth-protected-resource/mcp"
    )
    metadata = protected_resource_metadata(
        resource=resource, issuer="https://auth.test/", scopes=["mail:read", "mail:read"]
    )
    assert metadata["authorization_servers"] == ["https://auth.test"]
    assert metadata["scopes_supported"] == ["mail:read"]
    api_key_only = protected_resource_metadata(resource=resource, issuer=None, scopes=["mail:read"])
    assert "authorization_servers" not in api_key_only
    assert api_key_only["scopes_supported"] == ["mail:read"]
    with pytest.raises(ValueError):
        protected_resource_metadata_url("http://mail.test/mcp")

    principal = Principal.build(
        subject="u",
        client_id="codex",
        scopes=["mail:metadata"],
        audience=resource,
        issuer="https://auth.test",
    )
    tools = visible_tools(principal, ["service_info", "get_message", "delete", "unknown"])
    assert tools == ["service_info"]
    assert "approve" in FORBIDDEN_TOOL_NAMES
    require_scope(principal, "mail:metadata")
    with pytest.raises(InsufficientScope):
        require_scope(principal, "mail:draft")


def test_rfc8414_discovery_inserts_well_known_and_validates_security_fields() -> None:
    assert (
        authorization_server_metadata_url("https://auth.test/tenant/")
        == "https://auth.test/.well-known/oauth-authorization-server/tenant"
    )
    assert authorization_server_metadata_url("https://auth.test") == (
        "https://auth.test/.well-known/oauth-authorization-server"
    )
    with pytest.raises(ValueError):
        authorization_server_metadata_url("https://user:pass@auth.test")
