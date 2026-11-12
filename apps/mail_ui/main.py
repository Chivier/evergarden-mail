from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets
import stat
import uuid
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, SecretStr

from apps.mail_ui.bridge import install_bridge_routes
from evergarden.audit.redaction import configure_logging, redact_error_detail
from evergarden.auth.admin_session import (
    AdminAuthError,
    AdminSession,
    AdminSessionAuth,
    LoginThrottle,
    session_cookie_name,
)
from evergarden.auth.api_keys import ApiKeyConflict, ApiKeyError, ApiKeyManager
from evergarden.auth.discovery import protected_resource_metadata_url
from evergarden.auth.policy import supported_scopes
from evergarden.config import Settings, get_settings
from evergarden.mail.account_admin import (
    AccountAdminError,
    AccountConfigConflict,
    AccountConfigManager,
)
from evergarden.mail.sync_notice import summarize_sync_incomplete
from evergarden.mail.thunderbird_bridge import MAX_REQUEST_BYTES

MAX_UI_REQUEST_BYTES = 8 * 1024 * 1024
MAX_MCP_RESPONSE_BYTES = 8 * 1024 * 1024
ASSET_DIR = Path(__file__).with_name("static")
SHARED_ASSET_DIR = Path(__file__).resolve().parents[1] / "shared_static"
# Shared, non-sensitive assets: no mail data, served before login.
SHARED_PUBLIC_ASSETS = {
    "http.js": (SHARED_ASSET_DIR / "http.js", "text/javascript"),
    "i18n.js": (SHARED_ASSET_DIR / "i18n.js", "text/javascript"),
    "locale-en.js": (SHARED_ASSET_DIR / "locales" / "en.js", "text/javascript"),
    "locale-zh-CN.js": (SHARED_ASSET_DIR / "locales" / "zh-CN.js", "text/javascript"),
    "ui.js": (SHARED_ASSET_DIR / "ui.js", "text/javascript"),
    "tokens.css": (SHARED_ASSET_DIR / "tokens.css", "text/css"),
    "components.css": (SHARED_ASSET_DIR / "components.css", "text/css"),
    "logo.svg": (SHARED_ASSET_DIR / "logo.svg", "image/svg+xml"),
    "favicon.svg": (SHARED_ASSET_DIR / "favicon.svg", "image/svg+xml"),
}
MAIL_UI_ASSETS = {
    "app.js": (ASSET_DIR / "app.js", "text/javascript"),
    "bridge.js": (ASSET_DIR / "bridge.js", "text/javascript"),
    "login.js": (ASSET_DIR / "login.js", "text/javascript"),
    "styles.css": (ASSET_DIR / "styles.css", "text/css"),
    "feedback.js": (ASSET_DIR / "feedback.js", "text/javascript"),
    "feedback.css": (ASSET_DIR / "feedback.css", "text/css"),
    # Public: the login page needs the shared JSON helper, the i18n
    # runtime, its catalogues, styles and brand marks before a session exists.
    **SHARED_PUBLIC_ASSETS,
}
# A password check is a ~130 ms, 32 MiB scrypt run. It runs in a worker thread
# so the event loop keeps serving the workbench and the bridge, and at most
# LOGIN_CONCURRENCY run at once; a login that cannot get a slot quickly is
# answered 429 instead of queueing unbounded memory and CPU.
LOGIN_CONCURRENCY = 2
LOGIN_SLOT_WAIT_SECONDS = 0.5
# Execution must finish inside the gateway's 180 s /api/ read timeout.
MCP_EXECUTE_TIMEOUT_SECONDS = 150.0
MCP_PREPARE_TIMEOUT_SECONDS = 60.0
MCP_DEFAULT_TIMEOUT_SECONDS = 15.0
logger = logging.getLogger(__name__)

UI_TOOLS = frozenset(
    {
        "service_info",
        "health_status",
        "list_accounts",
        "list_folders",
        "sync_status",
        "sync_mail",
        "oauth_status",
        "find_verification_codes",
        "get_mail_preferences",
        "edit_global_notes",
        "edit_mailbox_preferences",
        "list_recent",
        "count_mail",
        "diagnose_message",
        "submit_mail_feedback",
        "get_mail_feedback",
        "list_mail_feedback",
        "mailbox_stats",
        "search_mail",
        "get_message",
        "get_thread",
        "list_attachments",
        "download_attachment",
        "stage_attachment",
        "get_draft_status",
        "prepare_send",
        "prepare_reply",
        "prepare_forward",
        "send_approved",
        "preview_archive",
        "archive_approved",
        "preview_move_unrelated",
        "move_unrelated_approved",
        "preview_move",
        "move_approved",
        "preview_mark",
        "mark_approved",
        "preview_trash",
        "trash_approved",
    }
)


class ToolRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


class AddAccountRequest(BaseModel):
    expected_revision: str = Field(min_length=64, max_length=64)
    account: dict[str, Any]


class AccountStateRequest(BaseModel):
    expected_revision: str = Field(min_length=64, max_length=64)
    enabled: bool


class CreateApiKeyRequest(BaseModel):
    expected_revision: str = Field(min_length=64, max_length=64)
    label: str = Field(min_length=1, max_length=48)
    scopes: list[str] = Field(min_length=1, max_length=32)
    ttl_days: int = Field(ge=1, le=365)


class RevokeApiKeyRequest(BaseModel):
    expected_revision: str = Field(min_length=64, max_length=64)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=1024)


class McpTransportError(RuntimeError):
    """The internal MCP service could not return a trusted protocol response."""


class McpToolError(RuntimeError):
    """The MCP service returned a bounded tool-level error."""


class McpSyncIncomplete(McpToolError):
    """sync_mail attempted every mailbox, but at least one did not sync."""

    def __init__(self, failures: list[dict[str, Any]]):
        super().__init__(f"MAIL_SYNC_INCOMPLETE: {len(failures)} mailbox(es) did not sync")
        self.failures = failures


def _private_token(path: Path) -> str:
    if path.is_symlink():
        raise RuntimeError("mail UI MCP token must not be a symlink")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError("mail UI MCP token must be a regular mode-0600 file")
    if not 32 <= info.st_size <= 4096:
        raise RuntimeError("mail UI MCP token size is outside the safety bound")
    token = path.read_text(encoding="utf-8").strip()
    if len(token) < 32 or any(character.isspace() for character in token):
        raise RuntimeError("mail UI MCP token is malformed")
    return token


def mcp_call_timeout(name: str) -> float:
    if name.endswith("_approved") or name == "sync_mail":
        return MCP_EXECUTE_TIMEOUT_SECONDS
    if name.startswith(("prepare_", "preview_")):
        return MCP_PREPARE_TIMEOUT_SECONDS
    return MCP_DEFAULT_TIMEOUT_SECONDS


class McpGateway:
    """Narrow internal JSON-RPC client; provider credentials never enter the UI."""

    def __init__(self, *, url: str, token_file: Path):
        self.url = url
        self.token_file = token_file

    async def _rpc(self, method: str, params: dict[str, Any], *, timeout: float) -> Any:
        try:
            token = _private_token(self.token_file)
        except (RuntimeError, OSError) as exc:
            raise McpTransportError("mail UI internal MCP credential is unavailable") from exc
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        chunks: list[bytes] = []
        size = 0
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout), follow_redirects=False, trust_env=False
            ) as client:
                async with client.stream(
                    "POST",
                    self.url,
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                ) as response:
                    if response.status_code != 200:
                        raise McpTransportError("MCP request was rejected")
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_MCP_RESPONSE_BYTES:
                            raise McpTransportError("MCP response exceeds 8 MiB")
                        chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise McpTransportError("MCP did not respond in time") from exc
        except httpx.HTTPError as exc:
            raise McpTransportError("MCP is temporarily unavailable") from exc
        try:
            value = json.loads(b"".join(chunks))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpTransportError("MCP returned malformed JSON") from exc
        if not isinstance(value, dict) or value.get("id") != request_id:
            raise McpTransportError("MCP returned a mismatched response")
        if "error" in value:
            error = value["error"]
            message = error.get("message") if isinstance(error, dict) else None
            raise McpToolError(str(message or "MCP tool request failed")[:300])
        if not isinstance(value.get("result"), dict):
            raise McpTransportError("MCP returned a malformed result")
        return value["result"]

    async def ping(self) -> None:
        result = await self._rpc("ping", {}, timeout=MCP_DEFAULT_TIMEOUT_SECONDS)
        if result != {}:
            raise McpTransportError("MCP returned a malformed ping")

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        value = await self._rpc(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=mcp_call_timeout(name),
        )
        try:
            content = value["content"]
            text = next(item["text"] for item in content if item.get("type") == "text")
            if value.get("isError"):
                failures = summarize_sync_incomplete(text)
                if failures is not None:
                    raise McpSyncIncomplete(failures)
                raise McpToolError(redact_error_detail(text, limit=300))
            return json.loads(text)
        except (KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
            raise McpTransportError("MCP tool result is malformed") from exc


def throttle_key(value: str) -> str | None:
    """Return the login-throttle key for a client address, or None if invalid.

    An IPv6 client usually controls a whole /64 and can pick any source address
    inside it, so IPv6 clients share one bucket per /64. IPv4-mapped IPv6
    addresses count as the IPv4 address they carry.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((address, 64), strict=False))
    return str(address)


def create_app(
    settings: Settings | None = None,
    *,
    gateway: McpGateway | None = None,
    account_manager: AccountConfigManager | None = None,
    api_key_manager: ApiKeyManager | None = None,
    admin_auth: AdminSessionAuth | None = None,
    login_throttle: LoginThrottle | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    if settings.mail_ui_enabled:
        if settings.admin_session_key_file is None or settings.admin_credential_file is None:
            raise RuntimeError("enabled mail UI requires private administrator login files")
        if admin_auth is None:
            admin_auth = AdminSessionAuth(
                session_key_file=settings.admin_session_key_file,
                credential_file=settings.admin_credential_file,
                ttl_seconds=settings.admin_session_ttl_seconds,
                revocation_file=settings.admin_session_revocation_file,
            )
        if login_throttle is None:
            login_throttle = LoginThrottle(
                max_failures=settings.admin_login_max_failures,
                window_seconds=settings.admin_login_window_seconds,
            )
        if gateway is None:
            if settings.mail_ui_mcp_token_file is None:
                raise RuntimeError("enabled mail UI requires a private MCP token")
            gateway = McpGateway(
                url=settings.mail_ui_mcp_url,
                token_file=settings.mail_ui_mcp_token_file,
            )
        if settings.mail_ui_account_admin_enabled and account_manager is None:
            if settings.account_config_file is None:
                raise RuntimeError("account administration requires a private account config")
            account_manager = AccountConfigManager(settings.account_config_file)
        if settings.mail_ui_api_keys_enabled and api_key_manager is None:
            if settings.mcp_api_keys_file is None:
                raise RuntimeError("API key issuance requires a private key registry path")
            api_key_manager = ApiKeyManager(
                settings.mcp_api_keys_file,
                resource=str(settings.mcp_resource),
                mode=settings.mode,
            )

    app = FastAPI(title="Evergarden Mail Workbench", docs_url=None, redoc_url=None)
    login_slots = asyncio.Semaphore(LOGIN_CONCURRENCY)
    session_cookie = session_cookie_name(settings.admin_secure_cookies)

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > (
                    MAX_REQUEST_BYTES
                    if request.url.path.startswith("/bridge/")
                    else MAX_UI_REQUEST_BYTES
                ):
                    return JSONResponse({"detail": "request exceeds 8 MiB"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "invalid request length"}, status_code=400)
        request_id = uuid.uuid4().hex
        try:
            response = await call_next(request)
        except Exception as exc:
            if not request.url.path.startswith(("/api/", "/bridge/")):
                raise
            logger.error(
                "mail UI API failed request_id=%s path=%s error_class=%s",
                request_id,
                request.url.path,
                type(exc).__name__,
            )
            response = JSONResponse(
                {
                    "detail": "The service is temporarily unavailable. Refresh to check the state.",
                    "reason_code": "SERVICE_UNAVAILABLE",
                    "request_id": request_id,
                },
                status_code=500,
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; connect-src 'self'; img-src 'self' data:; "
            "object-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def identity(request: Request) -> AdminSession:
        if not settings.mail_ui_enabled or admin_auth is None:
            raise HTTPException(status_code=503, detail="mail UI is fenced off")
        try:
            return admin_auth.authenticate(request.cookies.get(session_cookie, ""))
        except AdminAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def require_csrf(request: Request, current: AdminSession) -> None:
        header = request.headers.get("x-csrf-token", "")
        if len(header) < 32 or not secrets.compare_digest(current.csrf, header):
            raise HTTPException(status_code=403, detail="valid CSRF token is required")

    install_bridge_routes(app, settings, identity, require_csrf)

    def client_key(request: Request) -> str:
        # The gateway replaces X-Forwarded-For with exactly one address: the
        # client its real-IP mode resolved (EVERGARDEN_GATEWAY_REAL_IP; the TCP
        # peer in the default direct mode). Only the right-most entry is read,
        # so a chain sent by anything else cannot rotate the throttle key; a
        # request without a valid address falls back to the TCP peer.
        forwarded = request.headers.get("x-forwarded-for", "").rsplit(",", 1)[-1].strip()
        key = throttle_key(forwarded)
        if key is not None:
            return key
        peer = request.client.host if request.client else ""
        return throttle_key(peer) or peer or "unknown"

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        if settings.mail_ui_enabled:
            try:
                await asyncio.wait_for(gateway.ping(), timeout=1.5)
            except Exception as exc:
                raise HTTPException(status_code=503, detail="MCP connection unavailable") from exc
        return {
            "ok": True,
            "enabled": settings.mail_ui_enabled,
            "account_admin_enabled": settings.mail_ui_account_admin_enabled,
            "authentication": "local-password",
        }

    @app.get("/login")
    async def login_page(request: Request):
        if not settings.mail_ui_enabled or admin_auth is None:
            raise HTTPException(status_code=503, detail="mail UI is fenced off")
        try:
            identity(request)
        except HTTPException as exc:
            if exc.status_code != 401:
                raise
        else:
            return RedirectResponse(url="/", status_code=303)
        return FileResponse(ASSET_DIR / "login.html", media_type="text/html")

    @app.post("/api/login")
    async def login(body: LoginRequest, request: Request):
        if not settings.mail_ui_enabled or admin_auth is None or login_throttle is None:
            raise HTTPException(status_code=503, detail="mail UI is fenced off")
        requester = client_key(request)
        retry_after = login_throttle.retry_after(requester)
        if retry_after:
            return JSONResponse(
                {"detail": "too many failed login attempts; try again later"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        try:
            async with asyncio.timeout(LOGIN_SLOT_WAIT_SECONDS):
                await login_slots.acquire()
        except TimeoutError:
            return JSONResponse(
                {"detail": "too many concurrent login attempts; try again shortly"},
                status_code=429,
                headers={"Retry-After": "1"},
            )
        try:
            subject = await run_in_threadpool(
                admin_auth.verify_login, body.username, body.password.get_secret_value()
            )
        except AdminAuthError as exc:
            login_throttle.failure(requester)
            raise HTTPException(
                status_code=401, detail="invalid administrator credentials"
            ) from exc
        finally:
            login_slots.release()
        login_throttle.success(requester)
        try:
            token, current = admin_auth.issue(subject)
        except AdminAuthError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        response = JSONResponse({"ok": True, "subject": current.subject})
        response.set_cookie(
            session_cookie,
            token,
            secure=settings.admin_secure_cookies,
            httponly=True,
            samesite="strict",
            max_age=admin_auth.ttl_seconds,
            path="/",
        )
        return response

    @app.post("/api/logout")
    async def logout(request: Request):
        current = identity(request)
        require_csrf(request, current)
        try:
            # Server-side: the signed cookie stays valid until it expires, so
            # logout signs out every session of this administrator everywhere.
            await run_in_threadpool(admin_auth.revoke, current.subject)
        except AdminAuthError as exc:
            logger.error(
                "mail UI logout could not record revocation error_class=%s", type(exc).__name__
            )
            response = JSONResponse(
                {
                    "detail": "Signed out in this browser, but other sessions stay valid: "
                    "the server could not record the logout.",
                    "reason_code": "LOGOUT_NOT_RECORDED",
                },
                status_code=503,
            )
        else:
            response = JSONResponse({"ok": True})
        response.delete_cookie(
            session_cookie,
            secure=settings.admin_secure_cookies,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return response

    @app.get("/")
    async def index(request: Request):
        try:
            identity(request)
        except HTTPException as exc:
            if exc.status_code == 401:
                return RedirectResponse(url="/login", status_code=303)
            raise
        if not (ASSET_DIR / "index.html").is_file():
            raise HTTPException(status_code=503, detail="mail UI assets are unavailable")
        return FileResponse(ASSET_DIR / "index.html", media_type="text/html")

    @app.get("/assets/{asset}")
    async def asset(asset: str, request: Request):
        allowed = MAIL_UI_ASSETS
        if asset not in allowed:
            raise HTTPException(status_code=404, detail="asset not found")
        if asset in {"app.js", "bridge.js", "feedback.js"}:
            identity(request)
        path, media_type = allowed[asset]
        return FileResponse(path, media_type=media_type)

    @app.get("/feedback")
    async def feedback_page(request: Request):
        try:
            identity(request)
        except HTTPException as exc:
            if exc.status_code == 401:
                from urllib.parse import quote

                return RedirectResponse(
                    url="/login?next="
                    + quote(
                        str(request.url.path)
                        + ("?" + request.url.query if request.url.query else ""),
                        safe="",
                    ),
                    status_code=303,
                )
            raise
        return FileResponse(ASSET_DIR / "feedback.html", media_type="text/html")

    @app.get("/api/session")
    async def session(request: Request):
        current = identity(request)
        return {
            "bridge_accounts": sorted(settings.thunderbird_bridge_account_set),
            "subject": current.subject,
            "csrf": current.csrf,
            "approval_url": settings.mail_ui_approval_url,
            "account_admin_enabled": settings.mail_ui_account_admin_enabled,
            "api_keys_enabled": settings.mail_ui_api_keys_enabled,
            # Public discovery values only; the UI's own MCP bearer never leaves the server.
            "mcp_resource": str(settings.mcp_resource),
            "mcp_discovery_url": protected_resource_metadata_url(str(settings.mcp_resource)),
            # The OAuth option is offered only when MCP can verify OAuth tokens.
            "mcp_oauth_enabled": settings.oauth_bearer_enabled,
            "oauth_issuer": str(settings.oauth_issuer) if settings.oauth_bearer_enabled else None,
            "mcp_scopes": list(supported_scopes()),
        }

    @app.post("/api/mcp/{tool}")
    async def call_tool(tool: str, body: ToolRequest, request: Request):
        current = identity(request)
        require_csrf(request, current)
        if tool not in UI_TOOLS:
            raise HTTPException(status_code=404, detail="mail tool is not available in this UI")
        if gateway is None:
            raise HTTPException(status_code=503, detail="MCP gateway is unavailable")
        try:
            return await gateway.call(tool, body.arguments)
        except McpTransportError as exc:
            # 503, not 502: Cloudflare replaces origin 502/504 bodies with its own
            # error page, which would hide this detail from the browser.
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except McpSyncIncomplete as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "detail": str(exc),
                    "reason_code": "MAIL_SYNC_INCOMPLETE",
                    "sync_failures": exc.failures,
                },
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/admin/accounts")
    async def accounts(request: Request):
        identity(request)
        if not settings.mail_ui_account_admin_enabled or account_manager is None:
            raise HTTPException(status_code=503, detail="account administration is fenced off")
        try:
            return account_manager.snapshot()
        except AccountAdminError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/admin/accounts")
    async def add_account(body: AddAccountRequest, request: Request):
        current = identity(request)
        require_csrf(request, current)
        if not settings.mail_ui_account_admin_enabled or account_manager is None:
            raise HTTPException(status_code=503, detail="account administration is fenced off")
        try:
            return account_manager.add(body.account, expected_revision=body.expected_revision)
        except AccountConfigConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except AccountAdminError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/admin/accounts/{alias}/state")
    async def set_account_state(alias: str, body: AccountStateRequest, request: Request):
        current = identity(request)
        require_csrf(request, current)
        if not settings.mail_ui_account_admin_enabled or account_manager is None:
            raise HTTPException(status_code=503, detail="account administration is fenced off")
        try:
            return account_manager.set_enabled(
                alias,
                enabled=body.enabled,
                expected_revision=body.expected_revision,
            )
        except AccountConfigConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except AccountAdminError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    def require_api_keys() -> ApiKeyManager:
        if not settings.mail_ui_api_keys_enabled or api_key_manager is None:
            raise HTTPException(status_code=503, detail="API key issuance is fenced off")
        return api_key_manager

    @app.get("/api/admin/api-keys")
    async def list_api_keys(request: Request):
        identity(request)
        manager = require_api_keys()
        try:
            return manager.snapshot()
        except ApiKeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/admin/api-keys")
    async def create_api_key(body: CreateApiKeyRequest, request: Request):
        current = identity(request)
        require_csrf(request, current)
        manager = require_api_keys()
        try:
            issued = manager.create(
                label=body.label,
                scopes=body.scopes,
                ttl_days=body.ttl_days,
                expected_revision=body.expected_revision,
            )
        except ApiKeyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ApiKeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Identity and grant only. The plaintext is never logged.
        logger.info(
            "mail UI issued an MCP API key client_id=%s scopes=%s actor=%s",
            issued["client_id"],
            " ".join(body.scopes),
            current.subject,
        )
        return issued

    @app.post("/api/admin/api-keys/{client_id}/revoke")
    async def revoke_api_key(client_id: str, body: RevokeApiKeyRequest, request: Request):
        current = identity(request)
        require_csrf(request, current)
        manager = require_api_keys()
        try:
            remaining = manager.revoke(client_id, expected_revision=body.expected_revision)
        except ApiKeyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ApiKeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        logger.info(
            "mail UI revoked an MCP API key client_id=%s actor=%s", client_id, current.subject
        )
        return remaining

    return app


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    uvicorn.run(
        create_app(settings),
        host="0.0.0.0",  # noqa: S104 - Compose publishes this port on host loopback only
        port=8020,
        access_log=False,
    )


if __name__ == "__main__":
    main()
