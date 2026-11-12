from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import logging
import time
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from evergarden.approvals.dispatcher import ApprovalDispatcher, approval_dispatch_kinds
from evergarden.approvals.service import (
    ApprovalError,
    ApprovalService,
    PostgresApprovalRepository,
    ProviderDefinitelyRejected,
    ProviderNotAttempted,
    ProviderOutcomeUnknown,
)
from evergarden.audit.redaction import configure_logging, redact_error_detail
from evergarden.auth.credential_store import read_key_file
from evergarden.auth.discovery import protected_resource_metadata, protected_resource_metadata_url
from evergarden.auth.models import AuthenticationRequired, AuthorizationError
from evergarden.auth.policy import TOOL_SCOPES, require_scopes, supported_scopes, visible_tools
from evergarden.auth.verifier import (
    CompatibilityTokenVerifier,
    CompositeVerifier,
    IntrospectionVerifier,
    JwtVerifier,
    Verifier,
)
from evergarden.automations.fence import FenceConfig, FenceRejected, SideEffectFence
from evergarden.config import Settings, get_settings
from evergarden.database import (
    WriterLeaseUnavailable,
    append_audit_event,
    mail_operations_status,
    writer_action_lease,
)
from evergarden.mail.diagnostics import REQUEST_ID, SERVICE_VERSION, LocationActionBlocked
from evergarden.mail.preferences import MailPreferenceStore
from evergarden.mail.runtime import MailRuntime, MailSyncBatchError
from evergarden.mcp.tools import TOOL_DEFINITIONS, ToolRuntime

JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2025-06-18"
AuditRecorder = Callable[..., str]
MAX_MCP_REQUEST_BYTES = 8 * 1024 * 1024
logger = logging.getLogger(__name__)


def _noop_audit(**_kwargs) -> str:
    return "not-persisted-test-recorder"


def _jsonrpc_result(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _www_authenticate(
    resource_metadata_url: str | None, scope: str | None = None, error: str | None = None
) -> str:
    # resource_metadata is only offered when that metadata names an
    # authorization server; otherwise it would invite a pointless OAuth attempt.
    params = [f'resource_metadata="{resource_metadata_url}"'] if resource_metadata_url else []
    if scope:
        params.append(f'scope="{scope}"')
    if error:
        params.append(f'error="{error}"')
    return "Bearer " + ", ".join(params) if params else "Bearer"


def _default_runtime(settings: Settings) -> tuple[Verifier, ToolRuntime, AuditRecorder]:
    verifiers: list[Verifier] = []
    if settings.oauth_jwks_url:
        verifiers.append(
            JwtVerifier(
                issuer=str(settings.oauth_issuer),
                resource=str(settings.mcp_resource),
                jwks_url=str(settings.oauth_jwks_url),
            )
        )
    if settings.compatibility_token_file:
        verifiers.append(
            CompatibilityTokenVerifier(
                settings.compatibility_token_file,
                resource=str(settings.mcp_resource),
                issuer=str(settings.oauth_issuer),
            )
        )
    if settings.mcp_api_keys_file:
        # Self-service keys are revocable, so this registry is re-read whenever
        # the file changes instead of being pinned at process start.
        verifiers.append(
            CompatibilityTokenVerifier(
                settings.mcp_api_keys_file,
                resource=str(settings.mcp_resource),
                issuer=str(settings.oauth_issuer),
                reload=True,
                optional=True,
            )
        )
    if settings.oauth_introspection_url:
        secret_file = settings.oauth_introspection_client_secret_file
        if secret_file is None or secret_file.stat().st_mode & 0o077:
            raise RuntimeError("OAuth introspection secret file must be mode 0600")
        secret = secret_file.read_text(encoding="utf-8").strip()
        if not secret:
            raise RuntimeError("OAuth introspection secret is empty")
        verifiers.append(
            IntrospectionVerifier(
                endpoint=str(settings.oauth_introspection_url),
                client_id=str(settings.oauth_introspection_client_id),
                client_secret=secret,
                issuer=str(settings.oauth_issuer),
                resource=str(settings.mcp_resource),
            )
        )
    verifier = CompositeVerifier(verifiers)
    master_key = read_key_file(settings.credential_key_file)
    mail = MailRuntime(settings)
    # One policy snapshot wires every service; never re-derive account
    # semantics here.
    policy = mail.policy
    preferences = MailPreferenceStore(mail.store, accounts=policy.accounts)
    approvals = ApprovalService(
        PostgresApprovalRepository(
            settings.database_url,
            key=master_key,
            host_id=settings.host_id,
        ),
        accounts=policy.accounts,
        auto_approve_kinds=settings.auto_approve_kinds,
        uidplus_move_accounts=policy.uidplus_move_accounts,
        receive_only_accounts=policy.receive_only_accounts,
        draft_lifetime=dt.timedelta(hours=settings.approval_draft_lifetime_hours),
    )
    fence = SideEffectFence(
        FenceConfig(
            host_id=settings.host_id,
            active_writer=settings.active_writer,
            writer_epoch=settings.writer_epoch,
            side_effects_enabled=settings.side_effects_enabled,
            trash_actions_enabled=settings.trash_actions_enabled,
        )
    )

    def execute_approved(**kwargs):
        if settings.mode != "production":
            return approvals.execute(
                **kwargs,
                fence=fence,
                lease=None,
                executor=mail.actions,
            )
        with writer_action_lease(
            settings.database_url,
            action_slot=str(kwargs["approval_id"]),
            host=settings.host_id,
            owner_epoch=settings.writer_epoch,
        ) as lease:
            return approvals.execute(
                **kwargs,
                fence=fence,
                lease=lease,
                executor=mail.actions,
            )

    runtime = ToolRuntime(
        archive=mail.archive_reader,
        approvals=approvals,
        execute_approved=execute_approved,
        accounts=policy.read_accounts,
        receive_only_accounts=policy.receive_only_accounts,
        mode=settings.mode,
        side_effects_enabled=settings.side_effects_enabled,
        trash_actions_enabled=settings.trash_actions_enabled,
        sync_provider=lambda account, limit: mail.sync_selected(account, per_folder_limit=limit),
        sent_metadata_provider=lambda account, since, before, limit: mail.list_sent_metadata(
            account,
            since=since,
            before=before,
            per_account_limit=limit,
        ),
        oauth_status_provider=mail.refresh_readiness,
        preferences=preferences,
        staged_attachments=mail.staged_attachments,
        operations_status_provider=lambda: mail_operations_status(settings.database_url),
        organization_capabilities_provider=mail.actions.organization_capabilities,
        uidplus_move_accounts=policy.uidplus_move_accounts,
        approval_dispatch_kinds=approval_dispatch_kinds(settings),
        approval_session=mail.actions.session,
        feedback_base_url=f"{urlsplit(str(settings.mcp_resource)).scheme}://{urlsplit(str(settings.mcp_resource)).netloc}",
    )
    return (
        verifier,
        runtime,
        lambda **kwargs: append_audit_event(settings.database_url, **kwargs),
    )


def _tool_audit_metadata(name: str, required: frozenset[str], arguments: dict) -> dict:
    metadata = {"tool": name, "required_scopes": sorted(required)}
    targets = [
        str(arguments[key])
        for key in ("stable_message_id", "message_id", "draft_id", "approval_id")
        if arguments.get(key)
    ]
    if targets:
        metadata["target_fingerprint"] = hashlib.sha256("\0".join(targets).encode()).hexdigest()
    return metadata


def create_app(
    settings: Settings | None = None,
    *,
    verifier: Verifier | None = None,
    runtime: ToolRuntime | None = None,
    audit_recorder: AuditRecorder | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    if verifier is None or runtime is None:
        default_verifier, default_runtime, default_audit = _default_runtime(settings)
        verifier = verifier or default_verifier
        runtime = runtime or default_runtime
        audit_recorder = audit_recorder or default_audit
    elif audit_recorder is None:
        audit_recorder = _noop_audit
    resource = str(settings.mcp_resource)
    oauth_enabled = settings.oauth_bearer_enabled
    metadata_url = protected_resource_metadata_url(resource) if oauth_enabled else None
    metadata = protected_resource_metadata(
        resource=resource,
        issuer=str(settings.oauth_issuer) if oauth_enabled else None,
        scopes=supported_scopes(),
    )
    dispatch_kinds = approval_dispatch_kinds(settings)
    dispatcher = (
        ApprovalDispatcher(
            runtime.approvals,
            runtime.execute_approved,
            kinds=dispatch_kinds,
            host=settings.host_id,
            session=runtime.approval_session,
            parallel=settings.approval_dispatch_parallel,
        )
        if dispatch_kinds
        else None
    )
    dispatch_task = None

    @asynccontextmanager
    async def lifespan(_app):
        nonlocal dispatch_task
        stop = asyncio.Event()
        if dispatcher is not None:
            dispatch_task = asyncio.create_task(dispatcher.run(stop))
        try:
            yield
        finally:
            # Stop between items; an in-flight provider action finishes first.
            if dispatcher is not None:
                dispatcher.stopping.set()
            stop.set()
            if dispatch_task is not None:
                await dispatch_task

    app = FastAPI(title="Evergarden MCP", docs_url=None, redoc_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/healthz")
    async def healthz() -> dict:
        return {
            "ok": True,
            "mode": settings.mode,
            "host": settings.host_id,
            "active_writer": settings.active_writer,
            "side_effects_enabled": settings.side_effects_enabled,
            "approval_dispatch": {
                "enabled": dispatcher is not None,
                "kinds": sorted(kind.value for kind in dispatch_kinds),
                "running": dispatch_task is not None and not dispatch_task.done(),
                "last_scan_at": dispatcher.last_scan_at if dispatcher else None,
                "last_error_class": dispatcher.last_error_class if dispatcher else None,
                "last_item_error_class": dispatcher.last_item_error_class if dispatcher else None,
                "last_result": dispatcher.last_result if dispatcher else {},
            },
        }

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/mcp")
    async def oauth_protected_resource() -> dict:
        return metadata

    async def authenticate(request: Request):
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer ") or not header[7:].strip():
            raise AuthenticationRequired("bearer access token is required")
        return await verifier.verify(header[7:].strip())

    async def record_tool(principal, outcome: str, audit_metadata: dict) -> None:
        await run_in_threadpool(
            audit_recorder,
            event_type="mcp.tool",
            actor=principal.subject,
            client_id=principal.client_id,
            outcome=outcome,
            metadata=audit_metadata,
        )

    @app.post("/mcp")
    async def mcp(request: Request):
        try:
            principal = await authenticate(request)
        except AuthorizationError as exc:
            return JSONResponse(
                {"error": exc.oauth_error},
                status_code=exc.status_code,
                headers={
                    "WWW-Authenticate": _www_authenticate(metadata_url, error=exc.oauth_error)
                },
            )
        raw_length = request.headers.get("content-length")
        try:
            if raw_length is not None and int(raw_length) > MAX_MCP_REQUEST_BYTES:
                return JSONResponse(
                    _jsonrpc_error(None, -32600, "Request exceeds 8 MiB"), status_code=413
                )
        except ValueError:
            return JSONResponse(_jsonrpc_error(None, -32600, "Invalid Request"), status_code=400)
        body = await request.body()
        if len(body) > MAX_MCP_REQUEST_BYTES:
            return JSONResponse(
                _jsonrpc_error(None, -32600, "Request exceeds 8 MiB"), status_code=413
            )
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return JSONResponse(_jsonrpc_error(None, -32700, "Parse error"), status_code=400)
        if not isinstance(payload, dict) or payload.get("jsonrpc") != JSONRPC_VERSION:
            return JSONResponse(
                _jsonrpc_error(
                    payload.get("id") if isinstance(payload, dict) else None,
                    -32600,
                    "Invalid Request",
                ),
                status_code=400,
            )
        request_id = payload.get("id")
        method = payload.get("method")
        if not isinstance(method, str) or not method:
            return JSONResponse(
                _jsonrpc_error(request_id, -32600, "Invalid Request"), status_code=400
            )
        params = payload.get("params", {})
        params = {} if params is None else params
        if not isinstance(params, dict):
            return JSONResponse(
                _jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400
            )
        if "id" not in payload:
            # Notifications never invoke tools or produce JSON-RPC responses.
            # This stateless transport has no cancellable task registry.
            if method.startswith("notifications/"):
                return Response(status_code=202)
            return JSONResponse(
                _jsonrpc_error(None, -32600, "Requests require an id"), status_code=400
            )
        if method == "initialize":
            return _jsonrpc_result(
                request_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "evergarden", "version": "0.1.0"},
                    "instructions": (
                        "Scoped mail service. Reads and drafts are scope-limited. Every write is "
                        "prepared first (prepare_*/preview_*), which returns an immutable review "
                        "packet. If the result has approval_id and execution_owner 'client', call "
                        "the matching *_approved tool with it. If it has requires_human_approval "
                        "and execution_owner 'server', a human approves it on the approval "
                        "surface and the server executes it; poll get_draft_status and do not "
                        "call *_approved. PROVIDER_NOT_ATTEMPTED means nothing changed and the "
                        "approval is retained; retry later. Trash always needs a human. Accounts "
                        "configured for UIDPLUS move copy, verify, then expunge only the moved "
                        "message by UID; no tool deletes permanently."
                    ),
                },
            )
        if method == "ping":
            return _jsonrpc_result(request_id, {})
        if method == "tools/list":
            names = visible_tools(principal, TOOL_DEFINITIONS)
            tools = [{"name": name, **TOOL_DEFINITIONS[name]} for name in names]
            return _jsonrpc_result(request_id, {"tools": tools})
        if method == "tools/call":
            name = str(params.get("name") or "")
            required = TOOL_SCOPES.get(name)
            if not required:
                return JSONResponse(_jsonrpc_error(request_id, -32602, "Unknown tool"))
            arguments = params.get("arguments", {})
            arguments = {} if arguments is None else arguments
            if not isinstance(arguments, dict):
                return JSONResponse(
                    _jsonrpc_error(request_id, -32602, "Invalid params"), status_code=400
                )
            audit_metadata = _tool_audit_metadata(name, required, arguments)
            correlation_id = str(uuid.uuid4())
            audit_metadata.update(request_id=correlation_id, service_version=SERVICE_VERSION)
            started = time.monotonic()

            async def record_failure(outcome: str, exc: Exception) -> None:
                detail = redact_error_detail(exc)
                failure = {
                    **audit_metadata,
                    "error_class": type(exc).__name__,
                    "error_detail": detail,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                }
                if exc.__cause__ is not None:
                    failure["cause_class"] = type(exc.__cause__).__name__
                    failure["cause_detail"] = redact_error_detail(exc.__cause__)
                await record_tool(principal, outcome, failure)
                logger.warning(
                    "MCP tool rejected tool=%s outcome=%s error_class=%s duration_ms=%s detail=%s request_id=%s service_version=%s",
                    name,
                    outcome,
                    type(exc).__name__,
                    failure["duration_ms"],
                    detail,
                    correlation_id,
                    SERVICE_VERSION,
                )

            try:
                require_scopes(principal, required)

                # IMAP/SMTP, archive reads and database calls are synchronous.
                # Waiting for one provider must not block ping or other clients.
                def invoke_tool():
                    token = REQUEST_ID.set(correlation_id)
                    try:
                        return runtime.call(name, arguments, principal)
                    finally:
                        REQUEST_ID.reset(token)

                value = await run_in_threadpool(invoke_tool)
                if isinstance(value, dict) and name in {
                    "diagnose_message",
                    "submit_mail_feedback",
                    "get_mail_feedback",
                    "list_mail_feedback",
                }:
                    value.update(request_id=correlation_id, service_version=SERVICE_VERSION)
                    audit_metadata["sync_run_id"] = value.get("sync_run_id") or value.get(
                        "current_location", {}
                    ).get("sync_run_id")
            except AuthorizationError as exc:
                await record_failure("DENIED", exc)
                required_header = " ".join(sorted(required))
                return JSONResponse(
                    {
                        "error": exc.oauth_error,
                        "required_scope": getattr(exc, "required", required_header),
                    },
                    status_code=exc.status_code,
                    headers={
                        "WWW-Authenticate": _www_authenticate(
                            metadata_url, scope=required_header, error=exc.oauth_error
                        )
                    },
                )
            except LocationActionBlocked as exc:
                await record_failure("LOCATION_BLOCKED", exc)
                detail = {
                    **exc.detail,
                    "error": str(exc),
                    "request_id": correlation_id,
                    "service_version": SERVICE_VERSION,
                }
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": json.dumps(detail)}],
                        "isError": True,
                    },
                )
            except (ApprovalError, TypeError, ValueError) as exc:
                await record_failure("REJECTED", exc)
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": redact_error_detail(exc)}],
                        "isError": True,
                    },
                )
            except FenceRejected as exc:
                await record_failure("FENCE_REJECTED", exc)
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": redact_error_detail(exc)}],
                        "isError": True,
                    },
                )
            except ProviderNotAttempted as exc:
                await record_failure("PROVIDER_NOT_ATTEMPTED", exc)
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"PROVIDER_NOT_ATTEMPTED: {redact_error_detail(exc)}. "
                                    "No mailbox change was made; an existing approval is "
                                    "kept. Retry the same call later."
                                ),
                            }
                        ],
                        "isError": True,
                    },
                )
            except WriterLeaseUnavailable as exc:
                await record_failure("LEASE_UNAVAILABLE", exc)
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    "WRITER_LEASE_UNAVAILABLE: this approval is already "
                                    "executing or writer control is inactive. Check "
                                    "get_draft_status before retrying."
                                ),
                            }
                        ],
                        "isError": True,
                    },
                )
            except (ProviderDefinitelyRejected, ProviderOutcomeUnknown) as exc:
                await record_failure(
                    "PROVIDER_UNKNOWN"
                    if isinstance(exc, ProviderOutcomeUnknown)
                    else "PROVIDER_REJECTED",
                    exc,
                )
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": redact_error_detail(exc)}],
                        "isError": True,
                    },
                )
            except MailSyncBatchError as exc:
                await record_failure("FAILED", exc)
                failures = []
                for failure in exc.failures:
                    summary = {
                        "account": failure["account"],
                        "error_class": failure["error_class"],
                        "error_detail": redact_error_detail(failure.get("error_detail", "")),
                    }
                    if failure.get("failed_folders"):
                        summary["failed_folders"] = [
                            {
                                "folder": item["folder"],
                                "error_class": item["error_class"],
                                "error_detail": redact_error_detail(item.get("error_detail", "")),
                            }
                            for item in failure["failed_folders"]
                        ]
                    failures.append(summary)
                value = {
                    "error": "mail_sync_incomplete",
                    "failed_accounts": failures,
                    "partial_results": [
                        {
                            "account": item["account"],
                            "auth": item.get("auth", "unknown"),
                            "inserted": item.get("inserted", 0),
                        }
                        for item in exc.results
                    ],
                }
                logger.error("MCP mail sync incomplete accounts=%s", len(failures))
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": json.dumps(value)}],
                        "isError": True,
                    },
                )
            except Exception as exc:
                await record_failure("FAILED", exc)
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": "internal tool failure"}],
                        "isError": True,
                    },
                )
            await record_tool(
                principal,
                "SUCCESS",
                {
                    **audit_metadata,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                },
            )
            logger.info(
                "MCP tool finished tool=%s request_id=%s sync_run_id=%s service_version=%s",
                name,
                correlation_id,
                audit_metadata.get("sync_run_id"),
                SERVICE_VERSION,
            )
            return _jsonrpc_result(
                request_id,
                {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}]},
            )
        # HTTP 404 signals a missing endpoint/session to MCP transports and
        # causes clients to initialize again. Unsupported RPCs are RPC errors.
        diagnostic_method = (
            method
            if method
            in {"resources/list", "resources/templates/list", "prompts/list", "logging/setLevel"}
            else "unknown"
        )
        logger.info("MCP unsupported method method=%s", diagnostic_method)
        return JSONResponse(_jsonrpc_error(request_id, -32601, "Method not found"))

    return app


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    uvicorn.run(create_app(settings), host="0.0.0.0", port=8000, access_log=False)  # noqa: S104


if __name__ == "__main__":
    main()
