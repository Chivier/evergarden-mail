"""Single-machine installs serve the web origin and MCP over loopback HTTP."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evergarden.auth.discovery import (
    authorization_server_metadata_url,
    protected_resource_metadata,
    protected_resource_metadata_url,
)
from evergarden.config import Settings, is_https_or_loopback_http


@pytest.mark.parametrize(
    ("url", "accepted"),
    [
        ("https://mail.example.com/mcp", True),
        ("http://127.0.0.1:8788/mcp", True),
        ("http://localhost:8788/mcp", True),
        ("http://[::1]:8788/mcp", True),
        ("http://mail.example.com/mcp", False),
        ("http://127.0.0.2/mcp", False),
        ("https://user:secret@mail.example.com/mcp", False),
        ("https://mail.example.com/mcp#x", False),
        ("ftp://127.0.0.1/mcp", False),
    ],
)
def test_mcp_resource_allows_https_or_loopback_http(url: str, accepted: bool) -> None:
    assert is_https_or_loopback_http(url) is accepted
    if accepted:
        settings = Settings(mcp_resource=url, oauth_issuer=url.rsplit("/", 1)[0])
        assert str(settings.mcp_resource).startswith(url.split(":", 1)[0])
        assert protected_resource_metadata_url(url).endswith(
            "/.well-known/oauth-protected-resource/mcp"
        )
    else:
        with pytest.raises(ValidationError):
            Settings(mcp_resource=url)
        with pytest.raises(ValidationError):
            Settings(oauth_issuer=url)


def test_loopback_discovery_metadata_and_remote_http_rejection() -> None:
    metadata = protected_resource_metadata(
        resource="http://127.0.0.1:8788/mcp",
        issuer="https://auth.example.invalid",
        scopes=["mail:read"],
    )
    assert metadata["resource"] == "http://127.0.0.1:8788/mcp"
    assert authorization_server_metadata_url("http://localhost:9000") == (
        "http://localhost:9000/.well-known/oauth-authorization-server"
    )
    with pytest.raises(ValueError, match="HTTPS"):
        authorization_server_metadata_url("http://auth.example.com")
    with pytest.raises(ValueError, match="HTTPS"):
        protected_resource_metadata_url("http://mail.example.com/mcp")


def test_empty_env_values_mean_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "EVERGARDEN_OAUTH_JWKS_URL",
        "EVERGARDEN_COMPATIBILITY_TOKEN_FILE",
        "EVERGARDEN_ACTIVE_WRITER",
    ):
        monkeypatch.setenv(key, "")
    monkeypatch.delenv("EVERGARDEN_HOST_ID", raising=False)
    settings = Settings()
    assert settings.oauth_jwks_url is None
    assert settings.compatibility_token_file is None
    assert settings.host_id == "default"
    assert settings.active_writer == "default"


def test_non_secure_admin_cookies_are_tied_to_a_loopback_http_origin() -> None:
    assert Settings(admin_secure_cookies=False).admin_secure_cookies is False
    assert not Settings(
        admin_secure_cookies=False, mail_ui_approval_url="http://localhost:18788"
    ).admin_secure_cookies
    assert Settings(mail_ui_approval_url="https://mail.example.com").admin_secure_cookies
    https = "https://mail.example.com"
    with pytest.raises(ValidationError, match="non-Secure admin cookies"):
        Settings(admin_secure_cookies=False, mail_ui_approval_url=https, approval_ui_enabled=True)
    # Without a browser surface (worker-only runtime.env) no cookie is ever set.
    assert not Settings(admin_secure_cookies=False, mail_ui_approval_url=https).approval_ui_enabled


def test_a_blanked_host_id_fails_instead_of_falling_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EVERGARDEN_HOST_ID", "")
    with pytest.raises(ValidationError, match="EVERGARDEN_HOST_ID is set but empty"):
        Settings()
    monkeypatch.setenv("EVERGARDEN_HOST_ID", "   ")
    with pytest.raises(ValidationError, match="host id"):
        Settings()
    # An explicit value still wins, and other empty optional values stay "unset".
    assert Settings(host_id="box").host_id == "box"
    monkeypatch.setenv("EVERGARDEN_HOST_ID", "box")
    monkeypatch.setenv("EVERGARDEN_OAUTH_JWKS_URL", "")
    assert Settings().host_id == "box"
    monkeypatch.delenv("EVERGARDEN_HOST_ID")
    assert Settings().host_id == "default"
