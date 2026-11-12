"""Every route of the browser apps must reach its own upstream through the gateway.

The gateway is one public origin in front of three apps. A route that is missing
from deploy/nginx/evergarden-gateway.conf silently falls through to the mail UI
and answers 404, which for a safety control such as approval revocation means
the control does not work. These tests parse the nginx configuration and apply
nginx's own location-selection rules to every route the apps declare.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

from apps.approval_ui.main import APPROVAL_ASSETS
from apps.approval_ui.main import create_app as create_approval_app
from apps.mail_ui.main import MAIL_UI_ASSETS, SHARED_PUBLIC_ASSETS
from apps.mail_ui.main import create_app as create_mail_app
from evergarden.config import Settings

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "deploy/nginx/evergarden-gateway.conf"
UPSTREAMS = {
    "evergarden_mcp": "mcp",
    "evergarden_approval_ui": "approval-ui",
    "evergarden_mail_ui": "mail-ui",
}
LOCATION = re.compile(r"location\s+(=|\^~)?\s*([^\s{]+)\s*\{")


def parse_locations(text: str) -> list[tuple[str, str, str | None]]:
    """Return (modifier, path, upstream) for each top-level server location."""
    locations: list[tuple[str, str, str | None]] = []
    for match in LOCATION.finditer(text):
        depth = 1
        index = match.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(text[index], 0)
            index += 1
        block = text[match.end() : index - 1]
        upstream = re.search(r"proxy_pass\s+http://([A-Za-z0-9_]+)\s*;", block)
        locations.append(
            (
                match.group(1) or "",
                match.group(2),
                UPSTREAMS[upstream.group(1)] if upstream else None,
            )
        )
    return locations


def route(locations: list[tuple[str, str, str | None]], path: str) -> str | None:
    """Select a location exactly as nginx does for configurations without regexes."""
    assert not any(
        path_.startswith("~") or modifier.startswith("~") for modifier, path_, _ in locations
    )
    for modifier, location, upstream in locations:
        if modifier == "=" and location == path:
            return upstream
    prefixes = [item for item in locations if item[0] != "=" and path.startswith(item[1])]
    assert prefixes, f"{path} matches no gateway location"
    return max(prefixes, key=lambda item: len(item[1]))[2]


def concrete_paths(app) -> list[str]:
    paths = []
    for item in app.routes:
        if not isinstance(item, APIRoute):
            continue
        paths.append(re.sub(r"\{[^}]+\}", "sample", item.path))
    return sorted(set(paths))


@pytest.fixture(scope="module")
def locations() -> list[tuple[str, str, str | None]]:
    return parse_locations(GATEWAY.read_text(encoding="utf-8"))


def test_parser_reads_the_gateway_locations(locations) -> None:
    by_path = {(modifier, path): upstream for modifier, path, upstream in locations}
    assert by_path[("=", "/approvals")] == "approval-ui"
    assert by_path[("^~", "/api/")] == "mail-ui"
    assert by_path[("", "/")] == "mail-ui"
    assert route(locations, "/approvals/batch") == "approval-ui"
    assert route(locations, "/api/login") == "mail-ui"
    assert route(locations, "/nowhere") == "mail-ui"
    assert route(locations, "/mcp") == "mcp"
    assert route(locations, "/.well-known/oauth-protected-resource/mcp") == "mcp"


def test_every_approval_ui_route_reaches_the_approval_ui(locations, tmp_path: Path) -> None:
    app = create_approval_app(Settings(archive_dir=tmp_path))
    paths = concrete_paths(app)
    assert "/approvals/revoke" in paths
    misrouted = []
    for path in paths:
        if path == "/healthz":
            # Container health probe only; the public /healthz is the mail UI's.
            continue
        if path == "/assets/sample":
            continue
        if route(locations, path) != "approval-ui":
            misrouted.append(path)
    for asset in APPROVAL_ASSETS:
        target = route(locations, f"/assets/{asset}")
        # Shared design-system files are identical in both apps; the mail UI
        # serves them publicly, so either upstream answers correctly.
        if target == "mail-ui" and asset in SHARED_PUBLIC_ASSETS:
            continue
        if target != "approval-ui":
            misrouted.append(f"/assets/{asset}")
    assert misrouted == []


def test_every_mail_ui_route_reaches_the_mail_ui(locations) -> None:
    app = create_mail_app(Settings())
    paths = concrete_paths(app)
    assert {"/api/login", "/api/logout", "/bridge/ingest", "/login"} <= set(paths)
    misrouted = [
        path for path in paths if path != "/assets/sample" and route(locations, path) != "mail-ui"
    ]
    misrouted += [
        f"/assets/{asset}"
        for asset in MAIL_UI_ASSETS
        if route(locations, f"/assets/{asset}") != "mail-ui"
    ]
    assert misrouted == []


def test_gateway_has_no_approval_route_the_app_does_not_serve(locations, tmp_path) -> None:
    app = create_approval_app(Settings(archive_dir=tmp_path))
    served = concrete_paths(app)
    stale = []
    for modifier, path, upstream in locations:
        if upstream != "approval-ui":
            continue
        if modifier == "=" and path.startswith("/assets/"):
            if path.removeprefix("/assets/") not in APPROVAL_ASSETS:
                stale.append(path)
        elif modifier == "=" and path not in served:
            stale.append(path)
        elif modifier == "^~" and not any(item.startswith(path) for item in served):
            stale.append(path)
    assert stale == []
