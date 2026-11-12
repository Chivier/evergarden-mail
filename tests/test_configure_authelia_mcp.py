from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from deploy.scripts import configure_authelia_mcp as authelia_mcp


def base_config() -> dict:
    return {
        "session": {"secret": "session-secret"},
        "identity_providers": {
            "oidc": {
                "hmac_secret": "hmac-secret",
                "jwks": [
                    {
                        "key_id": "old-key",
                        "algorithm": "RS256",
                        "use": "sig",
                        "key": "old-private-key",
                        "certificate_chain": "old-certificate",
                    }
                ],
                "lifespans": {
                    "access_token": "1h",
                    "refresh_token": "90m",
                },
                "clients": [
                    {
                        "client_id": "outline",
                        "client_secret": "outline-secret-digest",
                        "redirect_uris": ["https://example.test/callback"],
                    }
                ],
            }
        },
    }


def configured(**overrides: object) -> dict:
    values: dict[str, object] = {
        "resource": "https://mail.example.test/mcp",
        "codex_client_id": "codex-evergarden",
        "codex_redirect_uri": "http://127.0.0.1:32124/callback/codex-id",
        "claude_client_id": "claude-code-evergarden",
        "claude_redirect_uri": "http://localhost:32125/callback",
        "refresh_token_lifespan": "30d",
    }
    values.update(overrides)
    return authelia_mcp.configure(base_config(), **values)  # type: ignore[arg-type]


def test_configure_adds_scopes_clients_and_client_specific_lifespan() -> None:
    result = configured()
    oidc = result["identity_providers"]["oidc"]
    assert oidc["lifespans"]["access_token"] == "1h"
    assert oidc["lifespans"]["refresh_token"] == "90m"
    assert oidc["lifespans"]["custom"][authelia_mcp.LIFESPAN_NAME] == {
        "access_token": "1h",
        "refresh_token": "30d",
        "id_token": "1h",
        "authorize_code": "1m",
    }
    assert set(oidc["scopes"]) == set(authelia_mcp.MCP_SCOPES)
    clients = {client["client_id"]: client for client in oidc["clients"]}
    assert clients["outline"]["client_secret"] == "outline-secret-digest"
    for client_id in ("codex-evergarden", "claude-code-evergarden"):
        client = clients[client_id]
        assert client["public"] is True
        assert client["authorization_policy"] == "two_factor"
        assert client["pkce_challenge_method"] == "S256"
        assert client["audience"] == ["https://mail.example.test/mcp"]
        assert client["lifespan"] == authelia_mcp.LIFESPAN_NAME
        assert client["pre_configured_consent_duration"] == "30d"
        assert client["access_token_signed_response_alg"] == "RS256"
        assert client["grant_types"] == ["authorization_code", "refresh_token"]
        assert set(client["scopes"]) == {
            "openid",
            "offline_access",
            *authelia_mcp.MCP_SCOPES,
        }


def test_configure_is_idempotent_and_rotates_only_active_signing_key() -> None:
    first = configured(signing_key="new-private-key", signing_key_id="key-20260820")
    second = authelia_mcp.configure(
        first,
        resource="https://mail.example.test/mcp",
        codex_client_id="codex-evergarden",
        codex_redirect_uri="http://127.0.0.1:32124/callback/codex-id",
        claude_client_id="claude-code-evergarden",
        claude_redirect_uri="http://localhost:32125/callback",
        refresh_token_lifespan="30d",
    )
    assert first == second
    oidc = first["identity_providers"]["oidc"]
    assert oidc["hmac_secret"] == "hmac-secret"
    assert oidc["jwks"][0]["key_id"] == "key-20260820"
    assert oidc["jwks"][0]["key"] == "new-private-key"
    assert "certificate_chain" not in oidc["jwks"][0]
    assert len(oidc["clients"]) == 3


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("resource", "http://mail.example.test/mcp", "HTTPS /mcp"),
        ("codex_redirect_uri", "http://127.0.0.1:32124/callback", "Codex callback path"),
        ("claude_redirect_uri", "http://127.0.0.1:32125/wrong", "Claude callback path"),
        ("refresh_token_lifespan", "forever", "lifespan"),
    ],
)
def test_configure_rejects_unsafe_inputs(field: str, value: str, message: str) -> None:
    with pytest.raises(RuntimeError, match=message):
        configured(**{field: value})


def test_cli_writes_private_candidate_without_printing_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "configuration.yml"
    candidate = tmp_path / "configuration.next.yml"
    source.write_text(yaml.safe_dump(base_config()), encoding="utf-8")
    source.chmod(0o600)
    monkeypatch.setattr(
        authelia_mcp,
        "_new_rsa_private_key",
        lambda: "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n",
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "configure-authelia-mcp",
            "--config",
            str(source),
            "--output",
            str(candidate),
            "--resource",
            "https://mail.example.test/mcp",
            "--codex-redirect-uri",
            "http://127.0.0.1:32124/callback/codex-id",
            "--claude-redirect-uri",
            "http://localhost:32125/callback",
            "--rotate-signing-key",
            "--signing-key-id",
            "key-20260820",
        ],
    )
    assert authelia_mcp.main() == 0
    assert candidate.stat().st_mode & 0o077 == 0
    assert "private-material" in candidate.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    assert "private-material" not in output
    assert "session-secret" not in output
    assert "no secret values were printed" in output
