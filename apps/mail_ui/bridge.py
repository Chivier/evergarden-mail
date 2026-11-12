"""Receive-only Thunderbird bridge on the workbench's existing origin."""

from __future__ import annotations

import io
import json
import threading
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from evergarden.auth.credential_store import read_key_file
from evergarden.mail.thunderbird_bridge import (
    MAX_REQUEST_BYTES,
    BridgeClients,
    BridgeError,
    BridgeMailbox,
)

ADDON_DIR = Path(__file__).resolve().parent / "thunderbird"
if not ADDON_DIR.is_dir():
    ADDON_DIR = Path(__file__).resolve().parents[2] / "addons" / "thunderbird"


def addon_bytes(resource: str = "https://evergarden.example.invalid/mcp") -> bytes:
    parsed = urlsplit(resource)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BridgeError("Thunderbird bridging requires a public HTTPS origin")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("manifest.json", "background.js", "options.html", "options.js"):
            content = (ADDON_DIR / name).read_text()
            if name == "manifest.json":
                manifest = json.loads(content)
                manifest["permissions"] = [
                    item for item in manifest["permissions"] if not item.startswith("https://")
                ]
                manifest["permissions"].append(origin + "/*")
                content = json.dumps(manifest)
            elif name == "background.js":
                content = content.replace(
                    'const ORIGIN = "https://evergarden.example.invalid";',
                    "const ORIGIN = " + json.dumps(origin) + ";",
                )
            archive.writestr(name, content)
    return stream.getvalue()


def install_bridge_routes(app, settings, identity, require_csrf):
    clients = BridgeClients(settings)
    mailbox = None
    mailbox_lock = threading.Lock()

    def enabled():
        if not settings.mail_ui_enabled or not settings.thunderbird_bridge_accounts.strip():
            raise HTTPException(503, "Thunderbird bridge is not enabled")

    def db():
        nonlocal mailbox
        with mailbox_lock:
            if mailbox is None:
                mailbox = BridgeMailbox(
                    settings.archive_dir, attachment_key=read_key_file(settings.credential_key_file)
                )
            return mailbox

    async def body(request, maximum=MAX_REQUEST_BYTES):
        chunks = bytearray()
        async for chunk in request.stream():
            chunks.extend(chunk)
            if len(chunks) > maximum:
                raise HTTPException(413, "bridge request is too large")
        try:
            value = json.loads(chunks)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(400, "invalid bridge JSON") from exc

    def client(request):
        enabled()
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "bridge authentication is required")
        try:
            return clients.authenticate(authorization[7:])
        except BridgeError as exc:
            raise HTTPException(401, "bridge authentication is required") from exc

    @app.post("/bridge/ingest")
    async def ingest(request: Request):
        current = await run_in_threadpool(client, request)
        value = await body(request)
        try:
            return await run_in_threadpool(lambda: db().receive(current, value))
        except BridgeError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/bridge/heartbeat")
    async def heartbeat(request: Request):
        current = await run_in_threadpool(client, request)
        value = await body(request, 2048)
        if set(value) != {"pending", "state"}:
            raise HTTPException(400, "invalid heartbeat")
        try:
            await run_in_threadpool(lambda: db().heartbeat(current["account"], **value))
        except BridgeError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True}

    @app.get("/bridge/status")
    def status(request: Request):
        identity(request)
        enabled()
        return {"accounts": db().status(clients.accounts(), clients.paired_accounts())}

    @app.post("/bridge/pair")
    async def pair(request: Request):
        require_csrf(request, identity(request))
        enabled()
        value = await body(request, 2048)
        if set(value) != {"account"} or not isinstance(value["account"], str):
            raise HTTPException(400, "invalid pairing request")
        try:
            result = await run_in_threadpool(clients.pair, value["account"])
        except BridgeError as exc:
            raise HTTPException(400, str(exc)) from exc
        return Response(
            json.dumps(result),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="evergarden-bridge.json"'},
        )

    @app.post("/bridge/revoke")
    async def revoke(request: Request):
        require_csrf(request, identity(request))
        enabled()
        value = await body(request, 2048)
        if set(value) != {"account"} or value["account"] not in clients.accounts():
            raise HTTPException(400, "invalid mailbox")
        await run_in_threadpool(clients.revoke, value["account"])
        return {"ok": True}

    @app.get("/bridge/addon.xpi")
    def addon(request: Request):
        identity(request)
        enabled()
        return Response(
            addon_bytes(str(settings.mcp_resource)),
            media_type="application/x-xpinstall",
            headers={"Content-Disposition": 'attachment; filename="evergarden-thunderbird.xpi"'},
        )

    @app.get("/bridge/notifications")
    def notifications(request: Request, after: int = 0):
        identity(request)
        enabled()
        if not 0 <= after <= 2**63 - 1:
            raise HTTPException(400, "invalid notification cursor")
        return db().notifications(after=after)

    @app.post("/bridge/notifications/read")
    async def acknowledge(request: Request):
        require_csrf(request, identity(request))
        enabled()
        value = await body(request, 2048)
        through = value.get("through")
        if set(value) != {"through"} or type(through) is not int or not 0 <= through <= 2**63 - 1:
            raise HTTPException(400, "invalid notification cursor")
        await run_in_threadpool(lambda: db().acknowledge(through))
        return {"ok": True}
