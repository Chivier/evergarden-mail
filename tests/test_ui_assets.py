"""Every page links only assets its app serves, and every page loads the
shared i18n runtime, both catalogues, the design tokens and the favicon."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.approval_ui.main import create_app as create_approval_app
from apps.mail_ui.main import create_app as create_mail_app
from evergarden.approvals.service import ApprovalRepository, ApprovalService
from evergarden.auth.admin_session import SESSION_COOKIE, AdminSessionAuth, credential_document
from evergarden.config import Settings

ROOT = Path(__file__).resolve().parents[1]
MAIL_PAGES = ["index.html", "login.html", "feedback.html"]
APPROVAL_PAGES = ["review.html", "send.html", "oauth.html"]
REQUIRED = [
    "/assets/i18n.js",
    "/assets/locale-en.js",
    "/assets/locale-zh-CN.js",
    "/assets/tokens.css",
    "/assets/components.css",
    "/assets/favicon.svg",
]
# Public before login: the login page itself must render and translate.
LOGIN_PUBLIC = {
    "/assets/http.js",
    "/assets/i18n.js",
    "/assets/locale-en.js",
    "/assets/locale-zh-CN.js",
    "/assets/tokens.css",
    "/assets/components.css",
    "/assets/styles.css",
    "/assets/login.js",
    "/assets/logo.svg",
    "/assets/favicon.svg",
}
CONTENT_TYPES = {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml"}


def _private(path: Path, value: str) -> Path:
    path.write_text(value)
    path.chmod(0o600)
    return path


def _asset_references(page: Path) -> list[str]:
    html = page.read_text()
    return re.findall(r'(?:src|href)="(/assets/[^"]+)"', html)


def _mail_client(tmp_path: Path) -> TestClient:
    password = "correct horse battery staple"
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=tmp_path / "token",
        admin_credential_file=_private(
            tmp_path / "admin.json", json.dumps(credential_document("admin", password))
        ),
        admin_session_key_file=_private(
            tmp_path / "admin-session", base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode()
        ),
        admin_secure_cookies=False,
    )
    return TestClient(create_mail_app(settings)), password


def _approval_client(tmp_path: Path) -> TestClient:
    key = _private(
        tmp_path / "approval-session", base64.urlsafe_b64encode(b"a" * 32).rstrip(b"=").decode()
    )
    token, _session = AdminSessionAuth(session_key_file=key).issue("admin")
    settings = Settings(
        approval_ui_enabled=True,
        oauth_callback_enabled=True,
        admin_session_key_file=key,
        admin_secure_cookies=False,
    )
    client = TestClient(
        create_approval_app(settings, approvals=ApprovalService(ApprovalRepository()))
    )
    client.cookies.set(SESSION_COOKIE, token)
    return client


@pytest.mark.parametrize(
    ("folder", "page"),
    [("mail_ui", page) for page in MAIL_PAGES] + [("approval_ui", page) for page in APPROVAL_PAGES],
)
def test_every_page_loads_i18n_tokens_and_favicon(folder: str, page: str) -> None:
    html = (ROOT / "apps" / folder / "static" / page).read_text()
    references = _asset_references(ROOT / "apps" / folder / "static" / page)
    for asset in REQUIRED:
        assert asset in references, f"{page} does not load {asset}"
    # The runtime loads before its catalogues, and both before the transport.
    order = [references.index(name) for name in REQUIRED[:3]]
    assert order == sorted(order)
    assert references.index("/assets/locale-zh-CN.js") < references.index("/assets/http.js")
    # Light-only pages would ignore the dark tokens.
    assert 'content="light"' not in html
    assert re.search(r"<title[^>]*>[^<]+ · Evergarden</title>", html)
    assert "data-lang-switch" in html


def test_mail_pages_reference_only_served_assets(tmp_path: Path) -> None:
    client, password = _mail_client(tmp_path)
    login_assets = set(_asset_references(ROOT / "apps/mail_ui/static/login.html"))
    assert login_assets <= LOGIN_PUBLIC
    for asset in sorted(login_assets):
        response = client.get(asset)
        assert response.status_code == 200, asset
        expected = CONTENT_TYPES[Path(asset).suffix]
        assert response.headers["content-type"].startswith(expected), asset
    response = client.post("/api/login", json={"username": "admin", "password": password})
    assert response.status_code == 200
    for page in MAIL_PAGES:
        for asset in _asset_references(ROOT / "apps/mail_ui/static" / page):
            assert client.get(asset).status_code == 200, f"{page}: {asset}"


def test_approval_pages_reference_only_served_assets(tmp_path: Path) -> None:
    client = _approval_client(tmp_path)
    for page in APPROVAL_PAGES:
        for asset in _asset_references(ROOT / "apps/approval_ui/static" / page):
            response = client.get(asset)
            assert response.status_code == 200, f"{page}: {asset}"
            expected = CONTENT_TYPES[Path(asset).suffix]
            assert response.headers["content-type"].startswith(expected), asset
    client.cookies.clear()
    assert client.get("/assets/i18n.js").status_code == 401


def test_shared_catalogues_are_served_byte_for_byte(tmp_path: Path) -> None:
    client, _password = _mail_client(tmp_path)
    shared = ROOT / "apps/shared_static"
    for asset, path in {
        "/assets/locale-en.js": shared / "locales/en.js",
        "/assets/locale-zh-CN.js": shared / "locales/zh-CN.js",
        "/assets/i18n.js": shared / "i18n.js",
        "/assets/logo.svg": shared / "logo.svg",
    }.items():
        assert client.get(asset).content == path.read_bytes()


def test_server_error_bodies_are_english_with_reason_codes() -> None:
    sources = "\n".join(
        (ROOT / path).read_text()
        for path in [
            "apps/mail_ui/main.py",
            "apps/approval_ui/main.py",
            "evergarden/auth/google_oauth.py",
            "evergarden/mail/credential_admin.py",
            "evergarden/approvals/service.py",
        ]
    )
    assert not re.search(r"[一-鿿]", sources)
    catalogue = (ROOT / "apps/shared_static/locales/en.js").read_text()
    for code in sorted(set(re.findall(r'"([A-Z][A-Z0-9_]{3,}): ', sources))):
        assert f'"server.{code}"' in catalogue, f"{code} has no UI translation"
    for code in sorted(set(re.findall(r'"reason_code": "([A-Z_]+)"', sources))):
        assert f'"server.{code}"' in catalogue, f"{code} has no UI translation"
    # The nginx gateway answers some failures itself with JSON reason codes.
    gateway = (ROOT / "deploy/nginx/evergarden-gateway.conf").read_text()
    gateway_codes = set(re.findall(r'\\?"reason_code\\?":\s*\\?"([A-Z_]+)', gateway))
    assert gateway_codes, "gateway reason codes moved; update this test"
    for name in ["en.js", "zh-CN.js"]:
        text = (ROOT / "apps/shared_static/locales" / name).read_text()
        for code in sorted(gateway_codes):
            assert f'"server.{code}"' in text, f"{code} has no {name} translation"
