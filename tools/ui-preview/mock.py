"""Preview server for the Evergarden web UIs with fictional data.

Serves the repository's real static files (HTML, JS, CSS, catalogues, logo)
under the production Content-Security-Policy and answers the JSON API with
made-up mailboxes, messages and approvals. It never imports project code and
never reads configuration, environment files or credentials.

    python3 tools/ui-preview/mock.py mail 48711 --approval-url http://127.0.0.1:48712
    python3 tools/ui-preview/mock.py approval 48712

Pass --empty to render empty states. Listens on 127.0.0.1 only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

APPS = Path(__file__).resolve().parents[2] / "apps"
SHARED = APPS / "shared_static"
CSP = (
    "default-src 'self'; base-uri 'none'; connect-src 'self'; img-src 'self' data:; "
    "object-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'"
)
TYPES = {
    ".js": "text/javascript",
    ".css": "text/css",
    ".html": "text/html",
    ".svg": "image/svg+xml",
}
SHARED_ASSETS = {
    "http.js": SHARED / "http.js",
    "i18n.js": SHARED / "i18n.js",
    "ui.js": SHARED / "ui.js",
    "locale-en.js": SHARED / "locales" / "en.js",
    "locale-zh-CN.js": SHARED / "locales" / "zh-CN.js",
    "tokens.css": SHARED / "tokens.css",
    "components.css": SHARED / "components.css",
    "logo.svg": SHARED / "logo.svg",
    "favicon.svg": SHARED / "favicon.svg",
}
NOW = dt.datetime.now(dt.UTC).replace(microsecond=0)


def iso(**delta: float) -> str:
    return (NOW + dt.timedelta(**delta)).isoformat()


ACCOUNTS = [
    {
        "alias": "personal",
        "email": "alex@example.com",
        "receive_only": False,
        "safe_move_folders": ["Archive", "Receipts", "Travel"],
        "archive_folder": "Archive",
    },
    {
        "alias": "work",
        "email": "alex.rivera@example.org",
        "receive_only": False,
        "safe_move_folders": ["Archive", "Projects"],
        "archive_folder": "Archive",
    },
    {
        "alias": "studio",
        "email": "hello@example.net",
        "receive_only": False,
        "safe_move_folders": ["Archive"],
        "archive_folder": "Archive",
    },
]
MESSAGES = [
    ("Morgan Lee", "Re: Storage migration proposal — notes before Thursday", "work"),
    ("Billing", "Your invoice for October is ready", "personal"),
    ("Sam Patel", "Draft agenda for the team offsite", "work"),
    ("Reading Group", "This month: The Left Hand of Darkness", "personal"),
    ("Accounts", "New sign-in from Firefox on Linux", "studio"),
    ("Priya Natarajan", "Photos from the weekend hike", "personal"),
    ("CI", "Build #4821 passed on main", "work"),
    ("Jordan Kim", "Re: Re: Travel reimbursement form and the receipts you asked for", "work"),
    ("Newsletter", "Garden notes: November edition", "personal"),
    ("Riley Chen", "Quote for the new studio website", "studio"),
    ("Morgan Lee", "Slides for Thursday", "work"),
    ("Library", "Your hold is ready for pickup", "personal"),
]
BODY = (
    "Hi Alex,\n\nThanks for sending the draft over. A few notes before Thursday:\n\n"
    "1. The storage numbers in section 2 look right, but the growth estimate assumes "
    "last year's rate.\n"
    "2. Could we move the rollout to the week of the 24th? That gives the support team "
    "time to update the runbook.\n"
    "3. I have attached the revised spreadsheet with the new projections.\n\n"
    "Happy to talk through any of this on a call tomorrow.\n\nBest,\nMorgan\n"
)


def message(index: int) -> dict:
    sender, subject, account = MESSAGES[index % len(MESSAGES)]
    return {
        "id": f"{index:024x}",
        "account": account,
        "folder": "INBOX",
        "subject": subject,
        "sender_name": sender,
        "sender_email": f"{sender.split()[0].lower()}@example.com",
        "date_received": iso(minutes=-41 * index - 7),
        "flags": [] if index % 3 == 0 else ["\\Seen"],
        "has_attachments": index % 4 == 0,
        "actionable": index != 5,
        "feedback_url": f"/feedback?message_id={index:024x}",
        "reason_code": "NO_ACTIVE_PROVIDER_LOCATION",
        "location_status": "missing",
    }


def draft_id(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


def draft(
    index: int, status: str = "pending_approval", phase: str = "pending", kind: str = "trash"
) -> dict:
    sender, subject, account = MESSAGES[index % len(MESSAGES)]
    summary = {
        "subject": subject,
        "sender": f"{sender} <{sender.split()[0].lower()}@example.com>",
        "account": account,
        "source_folder": "INBOX",
        "source_uid": 4000 + index,
        "date_received": iso(minutes=-90 * index - 30),
    }
    approval = None
    if status != "pending_approval":
        approval = {
            "approval_id": f"a-{index}",
            "source": "human" if index % 2 else "policy",
            "approved_by": "admin",
            "approved_at": iso(minutes=-6 * index - 2),
            "expires_at": None,
            "revoked_at": iso(minutes=-3) if status == "revoked" else None,
        }
    return {
        "draft_id": draft_id(index),
        "payload_hash": f"{index:064x}",
        "kind": kind,
        "status": status,
        "phase": phase,
        "created_at": iso(minutes=-12 * index - 3),
        "expires_at": iso(minutes=360 - 25 * index),
        "revocable": status == "approved",
        "attempt": 2 if status == "retryable" else 1,
        "error_class": "ProviderSourceGone" if status == "failed" else None,
        "summary": summary,
        "approval": approval,
        "review_packet": {
            **summary,
            "operation": kind,
            "destination": {"trash": "Deleted Items", "archive": "Archive", "move": "Projects"}.get(
                kind
            ),
            "stable_message_id": f"{index:024x}",
        },
    }


DISPATCH = {
    "enabled": True,
    "ready": True,
    "kinds": ["archive", "mark", "move", "send", "trash"],
    "last_scan_at": iso(seconds=-20),
    "queue": {"ready": 3},
    "activity": {
        "window_minutes": 10,
        "finished_recent": 12,
        "blocked": 0,
        "current": {
            "kind": "archive",
            "subject": MESSAGES[6][1],
            "account": "work",
            "draft_id": draft_id(90),
        },
    },
}
SEND = draft(77, kind="send")
# Index 77 would put the review window far in the past; keep it open.
SEND["expires_at"] = iso(minutes=300)
SEND["review_packet"] = {
    "operation": "reply",
    "account": "work",
    "from": "alex.rivera@example.org",
    "to": ["morgan.lee@example.com"],
    "cc": ["sam.patel@example.com"],
    "bcc": [],
    "subject": "Re: Storage migration proposal — notes before Thursday",
    "body": "Hi Morgan,\n\nThanks — moving the rollout to the 24th works for us. I have "
    "updated the projections in the attached sheet.\n\nSee you Thursday,\nAlex\n",
    "attachments": [
        {"filename": "storage-plan-v2.xlsx", "mimetype": "application/vnd.ms-excel", "size": 48213}
    ],
}
SEND["approval_dispatch"] = DISPATCH


class Handler(BaseHTTPRequestHandler):
    server_version = "EvergardenPreview"
    mode = "mail"
    empty = False
    approval_url = ""

    def log_message(self, *_args) -> None:
        pass

    def send_body(self, body, content_type: str = "application/json", code: int = 200) -> None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path: Path) -> None:
        self.send_body(path.read_bytes(), TYPES[path.suffix])

    def do_GET(self) -> None:
        self.route({})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        self.route(json.loads(raw or b"{}"))

    def route(self, body: dict) -> None:
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        static = APPS / ("mail_ui" if self.mode == "mail" else "approval_ui") / "static"
        if path.startswith("/assets/"):
            name = path.removeprefix("/assets/")
            if name in SHARED_ASSETS:
                return self.send_file(SHARED_ASSETS[name])
            if re.fullmatch(r"[a-z]+\.(js|css)", name) and (static / name).is_file():
                return self.send_file(static / name)
            return self.send_body({"detail": "asset not found"}, code=404)
        if self.mode == "mail":
            return self.mail(path, body)
        return self.approval(path, query)

    def mail(self, path: str, body: dict) -> None:
        static = APPS / "mail_ui" / "static"
        pages = {"/": "index.html", "/login": "login.html", "/feedback": "feedback.html"}
        if path in pages:
            return self.send_file(static / pages[path])
        if path == "/api/login":
            return self.send_body({"detail": "invalid administrator credentials"}, code=401)
        if path == "/api/session":
            return self.send_body(
                {
                    "subject": "admin",
                    "csrf": "preview-csrf-token-0000000000000000",
                    "approval_url": self.approval_url,
                    "account_admin_enabled": True,
                    "api_keys_enabled": True,
                    "mcp_resource": "https://mail.example.com/mcp",
                    "mcp_discovery_url": "https://mail.example.com/.well-known/oauth-protected-resource/mcp",
                    "oauth_issuer": "https://mail.example.com",
                    # Mirrors evergarden.auth.policy.supported_scopes().
                    "mcp_scopes": [
                        "mail:attachments",
                        "mail:delete",
                        "mail:draft",
                        "mail:metadata",
                        "mail:operations",
                        "mail:organize",
                        "mail:read",
                        "mail:send-approved",
                        "mail:settings",
                        "mail:sync",
                        "mail:verification",
                    ],
                    "bridge_accounts": [],
                }
            )
        if path.startswith("/api/mcp/"):
            return self.tool(path.removeprefix("/api/mcp/"), body.get("arguments", {}))
        if path == "/api/admin/api-keys":
            return self.send_body(
                {
                    "revision": "r1",
                    "max_keys": 32,  # evergarden.auth.api_keys.MAX_API_KEYS
                    "keys": [
                        {
                            "client_id": "laptop",
                            "scopes": ["mail:metadata", "mail:read", "mail:draft"],
                            "expires_at": iso(days=80),
                            "expired": False,
                        },
                    ],
                }
            )
        if path == "/api/admin/accounts":
            return self.send_body({"revision": "r1", "accounts": []})
        return self.send_body({"detail": "not found"}, code=404)

    def tool(self, name: str, arguments: dict) -> None:
        if name == "list_accounts":
            return self.send_body(ACCOUNTS)
        if name in {"list_recent", "search_mail"}:
            if arguments.get("paginated"):
                return self.send_body(
                    {"items": [{**message(5), "indexed_folder": "INBOX"}], "next_cursor": None}
                )
            return self.send_body([] if self.empty else [message(i) for i in range(12)])
        if name == "count_mail":
            return self.send_body(
                {
                    "count": 12,
                    "indexed_count": 12,
                    "actionable_count": 4,
                    "provider_present_count": 4,
                    "location_anomaly_count": 1,
                    "unverified_count": 0,
                }
            )
        if name == "get_message":
            return self.send_body(
                {
                    **message(0),
                    "recipients_to": "alex.rivera@example.org",
                    "recipients_cc": "sam.patel@example.com",
                    "body_text": BODY,
                }
            )
        if name == "list_attachments":
            return self.send_body(
                [
                    {
                        "attachment_id": "a1",
                        "filename": "storage-plan-v2.xlsx",
                        "mimetype": "application/vnd.ms-excel",
                        "size": 48213,
                        "available": True,
                    }
                ]
            )
        if name.startswith("preview_") or name.startswith("prepare_"):
            return self.send_body(
                {
                    "draft_id": draft_id(3),
                    "kind": name.split("_", 1)[1],
                    "execution_owner": "server",
                    "requires_human_approval": True,
                    "review_packet": draft(3)["review_packet"],
                }
            )
        if name == "list_mail_feedback":
            return self.send_body({"items": [], "next_cursor": None})
        if name == "diagnose_message":
            return self.send_body(
                {
                    "stable_message_id": arguments.get("stable_message_id"),
                    "reason_code": "NO_ACTIVE_PROVIDER_LOCATION",
                    "actionable": False,
                }
            )
        if name == "get_mail_preferences":
            return self.send_body({"global_notes": "", "mailboxes": {}, "revision": "r1"})
        return self.send_body({})

    def approval(self, path: str, query: dict) -> None:
        static = APPS / "approval_ui" / "static"
        pages = {"/review": "review.html", "/review/send": "send.html", "/oauth": "oauth.html"}
        if path in pages:
            return self.send_file(static / pages[path])
        if path == "/session":
            return self.send_body(
                {
                    "subject": "admin",
                    "csrf": "preview-csrf-token-0000000000000000",
                    "surface": "approval",
                }
            )
        if path == "/oauth/accounts":
            return self.send_body(
                {
                    "accounts": ["personal", "work"],
                    "providers": {"personal": "microsoft", "work": "google"},
                    "configured": {"personal": True, "work": True},
                }
            )
        if path == "/oauth/start/personal":
            return self.send_body(
                {
                    "flow": "device_code",
                    "flow_id": "preview",
                    "user_code": "WDJB-MJHT",
                    "verification_uri": "https://microsoft.com/devicelogin",
                    "expires_at": iso(minutes=15),
                    "interval": 900,
                }
            )
        match = re.fullmatch(r"/drafts/([0-9a-f-]{36})(/message)?", path)
        if match:
            index = int(match.group(1)[-4:])
            if match.group(2):
                mail = {
                    **message(index),
                    "recipients_to": "alex.rivera@example.org",
                    "recipients_cc": "",
                    "body_text": BODY,
                    "body_fetched": True,
                    "hash_matches": True,
                }
                return self.send_body({"available": True, "message": mail})
            if match.group(1) == draft_id(77):
                return self.send_body(SEND)
            value = draft(index)
            value["approval_dispatch"] = DISPATCH
            return self.send_body(value)
        if path == "/drafts":
            if query.get("view") == ["execution"]:
                states = [
                    ("approved", "running"),
                    ("attempting", "running"),
                    ("confirmed", "confirmed"),
                    ("failed", "failed"),
                    ("pending_approval", "pending"),
                    ("retryable", "running"),
                    ("confirmed", "confirmed"),
                    ("revoked", "failed"),
                ]
                kinds = ["trash", "archive", "move", "mark"]
                rows = (
                    []
                    if self.empty
                    else [
                        draft(i + 20, status, phase, kinds[i % 4])
                        for i, (status, phase) in enumerate(states * 2)
                    ]
                )
                return self.send_body(
                    {
                        "drafts": rows,
                        "has_more": False,
                        "approval_dispatch": DISPATCH,
                        "counts": {
                            "all": len(rows),
                            "pending": 2,
                            "running": 6,
                            "confirmed": 4,
                            "failed": 4,
                        },
                    }
                )
            rows = [] if self.empty else [draft(i) for i in range(1, 12)]
            other = [] if self.empty else [draft(40, kind="archive"), draft(41, kind="mark")]
            if query.get("select_all") == ["true"]:
                return self.send_body(
                    {
                        "drafts": [
                            {"draft_id": row["draft_id"], "payload_hash": row["payload_hash"]}
                            for row in rows
                        ]
                    }
                )
            return self.send_body(
                {
                    "drafts": rows,
                    "other_drafts": other,
                    "has_more": False,
                    "total": len(rows),
                    "other_total": len(other),
                    "approval_dispatch": DISPATCH,
                }
            )
        return self.send_body({"detail": "not found"}, code=404)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["mail", "approval"])
    parser.add_argument("port", type=int)
    parser.add_argument("--empty", action="store_true")
    parser.add_argument("--approval-url", default="http://127.0.0.1:48712")
    args = parser.parse_args()
    Handler.mode, Handler.empty, Handler.approval_url = args.mode, args.empty, args.approval_url
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
