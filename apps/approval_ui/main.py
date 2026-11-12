from __future__ import annotations

import datetime as dt
import hmac
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import httpx
import psycopg
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from apps.approval_ui.credentials import install_credential_routes
from evergarden.approvals.models import Actor
from evergarden.approvals.service import (
    ApprovalError,
    ApprovalRepository,
    ApprovalService,
    PostgresApprovalRepository,
)
from evergarden.archive.reader import ArchiveReader
from evergarden.auth.admin_session import (
    AdminAuthError,
    AdminSession,
    AdminSessionAuth,
    session_cookie_name,
)
from evergarden.auth.credential_store import read_key_file
from evergarden.auth.google_oauth import GoogleIdentityError
from evergarden.auth.oauth_coordinator import OAuthCoordinator, OAuthStateError
from evergarden.auth.provider_oauth import OAuthConfigurationError
from evergarden.config import Settings, get_settings
from evergarden.database import append_audit_event
from evergarden.mail.models import load_account_configs
from evergarden.mail.policy import AccountPolicy


class ApprovalRequest(BaseModel):
    draft_id: str
    payload_hash: str


class BatchApprovalRequest(BaseModel):
    items: list[ApprovalRequest] = Field(min_length=1, max_length=200)


class DevicePollRequest(BaseModel):
    flow_id: str = Field(min_length=20, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


ASSET_DIR = Path(__file__).with_name("static")
SHARED_ASSET_DIR = Path(__file__).resolve().parents[1] / "shared_static"
# Every asset the approval UI serves; the gateway test checks each is routed here.
APPROVAL_ASSETS = {
    "approval.css": (ASSET_DIR / "approval.css", "text/css"),
    "review.js": (ASSET_DIR / "review.js", "text/javascript"),
    "send.js": (ASSET_DIR / "send.js", "text/javascript"),
    "oauth.js": (ASSET_DIR / "oauth.js", "text/javascript"),
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
MAX_APPROVAL_REQUEST_BYTES = 256 * 1024
MAX_REVIEW_BODY_CHARS = 500_000
# The dispatcher beats after every item; one provider action can take a minute.
DISPATCHER_HEARTBEAT_MAX_AGE = dt.timedelta(seconds=120)
LOGGER = logging.getLogger("uvicorn.error")


def _is_json_path(path: str) -> bool:
    return path in {"/approvals", "/drafts", "/session"} or path.startswith(
        ("/approvals/", "/drafts/", "/oauth/")
    )


def create_app(
    settings: Settings | None = None,
    *,
    approvals: ApprovalService | None = None,
    oauth: OAuthCoordinator | None = None,
    admin_auth: AdminSessionAuth | None = None,
    audit_recorder: Callable[..., str] | None = None,
    archive_reader: ArchiveReader | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    # Read-only view of the local archive so reviewers can read the full mail an
    # archive/move/mark packet refers to. The packet itself stays the authority.
    archive_reader = archive_reader or ArchiveReader(
        settings.archive_dir, max_body_chars=MAX_REVIEW_BODY_CHARS
    )
    if settings.approval_ui_enabled or settings.oauth_callback_enabled:
        if settings.admin_session_key_file is None:
            raise RuntimeError("enabled approval UI requires a private admin session key")
        if admin_auth is None:
            admin_auth = AdminSessionAuth(
                session_key_file=settings.admin_session_key_file,
                ttl_seconds=settings.admin_session_ttl_seconds,
                revocation_file=settings.admin_session_revocation_file,
            )
    if approvals is None:
        repository = (
            PostgresApprovalRepository(
                settings.database_url,
                key=read_key_file(settings.credential_key_file),
                host_id=settings.host_id,
            )
            if settings.approval_ui_enabled
            else ApprovalRepository()
        )
        # Account semantics come from AccountPolicy, not raw settings sets:
        # policy intersects the bridge set with readable accounts and the
        # UIDPLUS set with enabled accounts (see evergarden/mail/policy.py).
        # The UI never executes writes itself, so an unreadable account file
        # falls back to the raw settings sets (a fail-closed superset for
        # receive-only) instead of refusing to start the approval surface.
        try:
            policy = AccountPolicy.build(
                settings, load_account_configs(settings.account_config_file)
            )
            accounts = policy.accounts
            uidplus_moves = policy.uidplus_move_accounts
            receive_only = policy.receive_only_accounts
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "approval UI falling back to raw account sets error_class=%s",
                type(exc).__name__,
            )
            accounts = ()
            uidplus_moves = settings.uidplus_move_account_set
            receive_only = settings.thunderbird_bridge_account_set
        approvals = ApprovalService(
            repository,
            accounts=accounts,
            uidplus_move_accounts=uidplus_moves,
            receive_only_accounts=receive_only,
        )
    if audit_recorder is None:
        audit_recorder = (
            (lambda **kwargs: append_audit_event(settings.database_url, **kwargs))
            if settings.approval_ui_enabled
            else (lambda **_kwargs: "")
        )
    app = FastAPI(title="Evergarden Approval UI", docs_url=None, redoc_url=None)
    session_cookie = session_cookie_name(settings.admin_secure_cookies)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _exc: RequestValidationError):
        # Validation details can echo input, including pasted credentials.
        return JSONResponse(
            {"detail": "Invalid request. Check the fields and try again."}, status_code=422
        )

    @app.exception_handler(ApprovalError)
    async def approval_error(_request: Request, exc: ApprovalError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(psycopg.Error)
    async def database_error(_request: Request, _exc: psycopg.Error):
        # English detail for API clients; the UI translates the reason code.
        return JSONResponse(
            {
                "detail": (
                    "The database is unavailable or the operation timed out. "
                    "Refresh the list to see what was approved, then retry."
                ),
                "reason_code": "DATABASE_UNAVAILABLE",
            },
            status_code=503,
        )

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        started = time.perf_counter()
        request.state.request_id = uuid.uuid4().hex
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > MAX_APPROVAL_REQUEST_BYTES:
                    return JSONResponse({"detail": "request exceeds 256 KiB"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "invalid request length"}, status_code=400)
        try:
            response = await call_next(request)
        except Exception as exc:
            if not _is_json_path(request.url.path):
                raise
            LOGGER.error(
                "approval_ui_failed request_id=%s path=%s error_class=%s",
                request.state.request_id,
                request.url.path,
                type(exc).__name__,
            )
            response = JSONResponse(
                {
                    "detail": "The service is temporarily unavailable. Refresh to check the state.",
                    "reason_code": "SERVICE_UNAVAILABLE",
                    "request_id": request.state.request_id,
                },
                status_code=500,
            )
        response.headers["X-Request-ID"] = request.state.request_id
        # Log timing and route only, never mail bodies, hashes, cookies or credentials.
        if request.url.path == "/drafts" or request.url.path.startswith("/approvals"):
            LOGGER.info(
                "approval_request id=%s path=%s status=%s duration_ms=%.1f",
                request.state.request_id,
                request.url.path,
                response.status_code,
                (time.perf_counter() - started) * 1000,
            )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; connect-src 'self'; img-src 'self'; "
            "object-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def require_admin(request: Request) -> AdminSession:
        if admin_auth is None:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        try:
            return admin_auth.authenticate(request.cookies.get(session_cookie, ""))
        except AdminAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def require_csrf(request: Request, current: AdminSession) -> None:
        header = request.headers.get("x-csrf-token", "")
        if len(header) < 32 or not hmac.compare_digest(current.csrf, header):
            raise HTTPException(status_code=403, detail="valid CSRF token is required")

    def login_redirect(request: Request) -> RedirectResponse:
        target = request.url.path
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return RedirectResponse(url=f"/login?next={quote(target, safe='')}", status_code=303)

    def dispatch_info() -> dict:
        row = approvals.repository.dispatcher_status()
        last_scan_at = row["last_scan_at"] if row else None
        ready = bool(
            last_scan_at is not None
            and approvals.now() - last_scan_at <= DISPATCHER_HEARTBEAT_MAX_AGE
        )
        return {
            "enabled": settings.approval_dispatch_enabled,
            "ready": ready,
            "kinds": list(row["kinds"]) if row else [],
            "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
            "last_error_class": row["last_error_class"] if row else None,
            "last_item_error_class": row["last_item_error_class"] if row else None,
            "last_result": row["last_result"] if row else {},
            "queue": {
                "ready": approvals.ready_human_count(),
            },
            "activity": {
                **approvals.dispatch_activity(),
                # Approvals skipped in the last scan because an earlier action on
                # the same message is still being verified.
                "blocked": int((row["last_result"] or {}).get("blocked", 0)) if row else 0,
            },
        }

    def require_dispatch(kinds: set[str]) -> dict:
        info = dispatch_info()
        if info["enabled"] and (not info["ready"] or not kinds <= set(info["kinds"])):
            raise HTTPException(
                status_code=503,
                detail=(
                    "APPROVAL_DISPATCHER_UNAVAILABLE: the approval dispatcher is not running "
                    "or does not handle this kind of operation, so approvals are paused. "
                    "Refresh later and retry."
                ),
            )
        return info

    @app.get("/healthz")
    async def healthz() -> dict:
        return {
            "ok": True,
            "enabled": settings.approval_ui_enabled,
            "oauth_callback_enabled": settings.oauth_callback_enabled,
        }

    @app.post("/approvals")
    def approve(
        body: ApprovalRequest,
        request: Request,
    ) -> dict:
        if not settings.approval_ui_enabled:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        current = require_admin(request)
        require_csrf(request, current)
        kind = approvals.repository.get_draft(body.draft_id).kind.value
        require_dispatch({kind})
        approval = approvals.approve(
            draft_id=body.draft_id,
            payload_hash=body.payload_hash,
            actor=Actor(current.subject, "approval-ui", "approval-ui", True),
        )
        value = asdict(approval)
        value["approved_at"] = approval.approved_at.isoformat()
        value["expires_at"] = (
            approval.expires_at.isoformat() if approval.expires_at is not None else None
        )
        value["approval_source"] = approval.approval_source.value
        return value

    @app.get("/drafts/{draft_id}")
    def review_draft(
        draft_id: str,
        request: Request,
    ) -> dict:
        if not settings.approval_ui_enabled:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        require_admin(request)
        try:
            value = approvals.review(draft_id)
        except ApprovalError as exc:
            raise HTTPException(status_code=404, detail="draft not found") from exc
        value["approval_dispatch"] = dispatch_info()
        return value

    @app.get("/drafts/{draft_id}/message")
    def review_draft_message(
        draft_id: str,
        request: Request,
    ) -> dict:
        """Return the archived mail a draft refers to, for display only."""
        if not settings.approval_ui_enabled:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        require_admin(request)
        try:
            draft = approvals.repository.get_draft(draft_id)
        except ApprovalError as exc:
            raise HTTPException(status_code=404, detail="draft not found") from exc
        packet = draft.payload or {}
        stable_id = packet.get("stable_message_id")
        if not isinstance(stable_id, str) or not stable_id:
            return {"available": False, "reason": "no_source_message"}
        try:
            message = archive_reader.get_message(stable_id)
        except ValueError:
            return {"available": False, "reason": "not_archived"}
        except Exception as exc:  # archive unreadable must not break the review page
            LOGGER.warning("approval_message_unavailable error_class=%s", type(exc).__name__)
            return {"available": False, "reason": "archive_unavailable"}
        expected = packet.get("raw_body_sha256")
        actual = message.pop("raw_body_sha256", None)
        message["hash_matches"] = (
            None if not expected or not actual else hmac.compare_digest(expected, actual)
        )
        return {"available": True, "message": message}

    @app.get("/drafts")
    def pending_trash(
        request: Request,
        offset: int = Query(0, ge=0),
        limit: int = Query(200, ge=1, le=200),
        select_all: bool = Query(False),
        view: Literal["pending", "execution"] = Query("pending"),
        status: Literal["all", "pending", "running", "confirmed", "failed"] = Query("all"),
    ) -> dict:
        if not settings.approval_ui_enabled:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        require_admin(request)
        if view == "execution":
            value = approvals.execution_page(limit=limit, offset=offset, status=status)
            value["approval_dispatch"] = dispatch_info()
            return value
        if select_all:
            return {
                "drafts": approvals.pending_trash_selection(),
                "has_more": False,
            }
        value = approvals.pending_trash_page(limit=limit, offset=offset)
        value["approval_dispatch"] = dispatch_info()
        return value

    @app.post("/approvals/batch")
    def approve_batch(body: BatchApprovalRequest, request: Request) -> dict:
        if not settings.approval_ui_enabled:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        current = require_admin(request)
        require_csrf(request, current)
        if len({item.draft_id for item in body.items}) != len(body.items):
            raise HTTPException(status_code=400, detail="duplicate draft IDs")
        require_dispatch({"trash"})
        results = approvals.approve_batch(
            items=[(item.draft_id, item.payload_hash) for item in body.items],
            actor=Actor(current.subject, "approval-ui", "approval-ui", True),
        )
        for result in results:
            approval = result.get("approval")
            if approval is None:
                continue
            result["approval"] = approvals.approval_summary(approval)
        LOGGER.info(
            "approval_batch id=%s requested=%d approved=%d failed=%d",
            request.state.request_id,
            len(body.items),
            sum(result["status"] in {"approved", "already_approved"} for result in results),
            sum(result["status"] == "failed" for result in results),
        )
        return {"results": results}

    @app.post("/approvals/revoke")
    def revoke_approvals(body: BatchApprovalRequest, request: Request) -> dict:
        if not settings.approval_ui_enabled:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        current = require_admin(request)
        require_csrf(request, current)
        if len({item.draft_id for item in body.items}) != len(body.items):
            raise HTTPException(status_code=400, detail="duplicate draft IDs")
        value = approvals.revoke(
            items=[(item.draft_id, item.payload_hash) for item in body.items],
            actor=Actor(current.subject, "approval-ui", "approval-ui", True),
        )
        revoked = value["revoked"]
        if revoked:
            audit_recorder(
                event_type="approval.revoked",
                actor=current.subject,
                client_id="approval-ui",
                outcome="SUCCESS",
                metadata={
                    "count": len(revoked),
                    "revoked": [
                        {
                            "approval_id": row["approval_id"],
                            "draft_id": row["draft_id"],
                            "previous_state": row["previous_state"],
                        }
                        for row in revoked
                    ],
                },
            )
        LOGGER.info(
            "approval_revoke id=%s requested=%d revoked=%d",
            request.state.request_id,
            len(body.items),
            len(revoked),
        )
        return {"results": value["results"]}

    @app.get("/session")
    async def session(request: Request, surface: str = Query("approval")):
        if surface not in {"oauth", "approval"}:
            raise HTTPException(status_code=400, detail="unknown human surface")
        current = require_admin(request)
        return {"subject": current.subject, "csrf": current.csrf, "surface": surface}

    @app.get("/review")
    @app.get("/review/send")
    async def review_page(request: Request):
        if not settings.approval_ui_enabled:
            raise HTTPException(status_code=503, detail="approval UI is fenced off")
        try:
            require_admin(request)
        except HTTPException as exc:
            if exc.status_code == 401:
                return login_redirect(request)
            raise
        page = "send.html" if request.url.path == "/review/send" else "review.html"
        return FileResponse(ASSET_DIR / page, media_type="text/html")

    @app.get("/oauth")
    async def oauth_page(request: Request):
        if not settings.oauth_callback_enabled:
            raise HTTPException(status_code=503, detail="interactive OAuth is fenced off")
        try:
            require_admin(request)
        except HTTPException as exc:
            if exc.status_code == 401:
                return login_redirect(request)
            raise
        return FileResponse(ASSET_DIR / "oauth.html", media_type="text/html")

    @app.get("/assets/{asset}")
    async def asset(asset: str, request: Request):
        require_admin(request)
        allowed = APPROVAL_ASSETS
        if asset not in allowed:
            raise HTTPException(status_code=404, detail="asset not found")
        path, media_type = allowed[asset]
        return FileResponse(path, media_type=media_type)

    install_credential_routes(app, settings, require_admin, require_csrf)

    @app.get("/oauth/accounts")
    def oauth_accounts(request: Request) -> dict:
        require_admin(request)
        if not settings.oauth_callback_enabled or oauth is None:
            raise HTTPException(status_code=503, detail="OAuth coordinator is unavailable")
        return {
            "accounts": sorted(oauth.clients),
            "providers": {
                alias: getattr(client, "provider", "microsoft")
                for alias, client in oauth.clients.items()
            },
            "configured": {
                alias: getattr(client, "configured", True)
                for alias, client in oauth.clients.items()
            },
            # "authorization_code" (browser redirect) or "device_code" (enter
            # a code at Microsoft's device sign-in page).
            "flows": {
                alias: getattr(client, "flow", "authorization_code")
                for alias, client in oauth.clients.items()
            },
            # The provider app's display name shown on its sign-in pages;
            # empty means the deployment did not declare one.
            "app_names": {
                alias: getattr(client, "app_name", "") for alias, client in oauth.clients.items()
            },
        }

    @app.get("/oauth/callback/{provider}")
    def provider_callback(
        request: Request,
        provider: str,
        state: str = Query(...),
        code: str | None = Query(default=None),
        error: str | None = Query(default=None),
    ) -> dict:
        if provider not in {"microsoft", "google"}:
            raise HTTPException(status_code=404, detail="unknown OAuth provider")
        if not settings.oauth_callback_enabled:
            raise HTTPException(status_code=503, detail="interactive OAuth callback is fenced off")
        require_admin(request)
        if error:
            raise HTTPException(status_code=400, detail="provider authorization was declined")
        if oauth is None or not code:
            raise HTTPException(status_code=503, detail="OAuth coordinator is unavailable")
        try:
            result = oauth.callback(state=state, code=code, provider=provider)
        except (OAuthStateError, GoogleIdentityError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OAuthConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (RuntimeError, httpx.HTTPError) as exc:
            raise HTTPException(
                status_code=502,
                detail="OAUTH_CALLBACK_FAILED: mailbox authorization did not complete; "
                "open the authorization page again.",
            ) from exc
        return RedirectResponse(
            url=f"/oauth?status=authorized&account={result['account']}", status_code=303
        )

    @app.post("/oauth/start/{account}")
    def start_provider_oauth(
        account: str,
        request: Request,
    ) -> dict:
        if not settings.oauth_callback_enabled:
            raise HTTPException(status_code=503, detail="interactive OAuth is fenced off")
        current = require_admin(request)
        require_csrf(request, current)
        if oauth is None:
            raise HTTPException(status_code=503, detail="OAuth coordinator is unavailable")
        try:
            return oauth.start(account)
        except OAuthStateError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OAuthConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (RuntimeError, httpx.HTTPError) as exc:
            raise HTTPException(
                status_code=502,
                detail="OAUTH_START_FAILED: mailbox authorization is temporarily unavailable; "
                "try again later.",
            ) from exc

    @app.post("/oauth/device/poll")
    def poll_device_oauth(body: DevicePollRequest, request: Request) -> dict:
        if not settings.oauth_callback_enabled:
            raise HTTPException(status_code=503, detail="interactive OAuth is fenced off")
        current = require_admin(request)
        require_csrf(request, current)
        if oauth is None:
            raise HTTPException(status_code=503, detail="OAuth coordinator is unavailable")
        try:
            return oauth.poll_device(body.flow_id)
        except OAuthStateError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (RuntimeError, httpx.HTTPError) as exc:
            raise HTTPException(
                status_code=502,
                detail="OAUTH_DEVICE_POLL_FAILED: Microsoft authorization has not completed "
                "yet; try again later.",
            ) from exc

    return app


def main() -> None:
    settings = get_settings()
    oauth = None
    if settings.oauth_callback_enabled:
        from evergarden.mail.runtime import MailRuntime

        runtime = MailRuntime(settings)
        oauth = OAuthCoordinator(store=runtime.store, clients=runtime.oauth_authorization_clients())
    # Container interface binding is safe because Compose publishes the port
    # only on the Docker host's loopback address.
    uvicorn.run(
        create_app(settings, oauth=oauth),
        host="0.0.0.0",  # noqa: S104 - host publication remains loopback-only
        port=8010,
        access_log=False,
    )


if __name__ == "__main__":
    main()
