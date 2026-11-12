#!/usr/bin/env python3
"""Prepare a fresh Evergarden install: private state, secrets and env files.

Run once from a clone, before the first ``docker compose up``:

    ./deploy/setup                       # or: python3 deploy/setup.py

It needs only the Python standard library (no ``uv sync``, sops or age) and
is idempotent: an existing secret, credential, runtime.env or .env is never
overwritten, so running it again only fills in what is missing.

What it creates under ``<root>/.local`` (directories 0700, files 0600):

- ``run/postgres_password`` (0640, read by the Postgres container through the
  deployment group) and the matching ``run/pgpass``;
- ``run/credential_store_key``, the key that encrypts stored mailbox passwords
  and OAuth tokens. Losing it loses those credentials;
- ``run/admin_session_key`` and ``run/admin_credentials.json`` (the generated
  administrator password is printed exactly once);
- ``run/mail_ui_mcp_token`` and ``run/compatibility_tokens.json``, the mail
  UI's own MCP grant;
- ``run/mail-config/mail_accounts.json`` with no mailboxes, and the
  ``run/mcp-api-keys`` directory for self-service MCP API keys;
- ``run/runtime.env`` from ``runtime.env.example`` with the generated values;
- ``data/{archive,secrets,reports,recovery}``.

It also writes ``<root>/.env`` (compose project name, UID/GID of the current
user, ports, the ``scheduler`` profile and the gateway's real-client-address
mode) from ``.env.example``; the mode of ``<root>`` itself is left alone.

``--real-ip`` tells the gateway where the client address comes from:
``direct`` (default; nothing in front, forwarding headers ignored), ``proxy``
(behind a reverse proxy, X-Forwarded-For from ``--trusted-proxies``) or
``cloudflare`` (proxy, plus CF-Connecting-IP from Cloudflare edge addresses).

The mail UI's own MCP grant is valid for a year. Run setup again with
``--renew-mail-ui-grant`` to extend it, then ``docker compose restart mcp``;
every run prints the current expiry.

The public origin decides cookie security: a loopback ``http://`` origin (the
default, ``http://127.0.0.1:8788``) gets non-Secure cookies; an ``https://``
origin for a reverse-proxy deployment gets Secure cookies.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
HOST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
# Mirrors evergarden.config.DEFAULT_HOST_ID (setup must run without the package).
DEFAULT_HOST_ID = "default"
PROJECT_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_HTTP_PORT = 8788
REAL_IP_MODES = ("direct", "proxy", "cloudflare")
# The mail UI's internal grant. It may do everything a person can do in the UI;
# mail:operations (operator diagnostics) stays with explicitly issued keys.
MAIL_UI_SCOPES = (
    "mail:attachments",
    "mail:delete",
    "mail:draft",
    "mail:metadata",
    "mail:organize",
    "mail:read",
    "mail:send-approved",
    "mail:settings",
    "mail:sync",
    "mail:verification",
)
# The MCP service refuses registry entries that expire later than 400 days out.
MAIL_UI_TOKEN_DAYS = 365


class SetupError(RuntimeError):
    """A precondition failed; nothing unsafe was written."""


# --- small filesystem helpers -------------------------------------------------


def require_own(path: Path) -> None:
    """Refuse a path another user owns, typically one Docker created as root."""
    owner = path.lstat().st_uid
    if owner != os.getuid():
        raise SetupError(
            f"{path} is owned by uid {owner}, not by you (uid {os.getuid()}). Docker creates "
            "root-owned directories when the stack is started before setup. Stop it with "
            "`docker compose down`, then give the path back to yourself, for example "
            f"`sudo chown -R $(id -u):$(id -g) {path}` (or remove it if it holds nothing "
            "yet), and run setup again"
        )


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise SetupError(f"{path} must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise SetupError(f"{path} must be a directory")
    require_own(path)
    path.chmod(0o700)


def write_new(path: Path, content: str, *, mode: int = 0o600, private_parent: bool = True) -> None:
    """Atomically create ``path``; refuse if anything already exists there.

    ``private_parent`` makes the parent a 0700 directory; it is off for files
    outside ``.local`` (``.env``), whose directory keeps its mode.
    """
    if path.exists() or path.is_symlink():
        raise SetupError(f"refusing to overwrite existing {path}")
    if private_parent:
        private_directory(path.parent)
    elif path.parent.is_symlink() or not path.parent.is_dir():
        raise SetupError(f"{path.parent} must be an existing directory, not a symlink")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        # link() fails if the target appeared meanwhile, unlike replace().
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def replace_private(path: Path, content: str) -> None:
    """Atomically replace an existing private file, keeping it 0600."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise


def existing_regular(path: Path) -> bool:
    if path.is_symlink():
        raise SetupError(f"{path} must not be a symlink")
    if not path.exists():
        return False
    if not stat.S_ISREG(path.stat().st_mode):
        raise SetupError(
            f"{path} exists but is not a regular file (Docker creates a directory when a "
            "bind-mounted file is missing; run `docker compose down`, remove it, with sudo "
            "if root owns it, and run setup again)"
        )
    return True


def read_private(path: Path) -> str:
    if path.stat().st_mode & 0o007:
        raise SetupError(f"{path} must not be readable by other users")
    return path.read_text(encoding="utf-8").strip()


# --- values -------------------------------------------------------------------


def normalize_origin(value: str) -> str:
    parts = urlsplit(value.strip())
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise SetupError("public origin must be a scheme://host[:port] URL without a path")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        raise SetupError(
            "a non-loopback public origin must use https:// (put a TLS reverse proxy in "
            "front, see deploy/reverse-proxy/); plain http is only allowed for 127.0.0.1, "
            "localhost or ::1"
        )
    try:
        parts.port  # noqa: B018 - validates the port number
    except ValueError as exc:
        raise SetupError("public origin has an invalid port") from exc
    return f"{parts.scheme}://{parts.netloc}"


def normalize_trusted_proxies(value: str) -> str:
    """Validate a space- or comma-separated list of proxy addresses/CIDRs.

    Returns the comma-separated form written to .env (the gateway entrypoint
    accepts both separators). ``none`` trusts no proxy.
    """
    entries = [item for item in re.split(r"[\s,]+", value.strip()) if item]
    if entries == ["none"]:
        return "none"
    if not entries:
        raise SetupError("--trusted-proxies needs at least one address or CIDR (or none)")
    networks = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise SetupError(f"trusted proxy {entry!r} is not an IP address or CIDR") from exc
        if network.prefixlen == 0:
            raise SetupError(f"trusted proxy {entry!r} would trust every address")
        networks.append(str(network))
    return ",".join(networks)


def is_loopback_http(origin: str) -> bool:
    parts = urlsplit(origin)
    return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


def credential_document(username: str, password: str) -> dict[str, object]:
    """Build the scrypt credential with the application's own implementation."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    # admin_session uses only the standard library, so this works before
    # `uv sync`; importing it keeps one source of truth for the hash format.
    from evergarden.auth.admin_session import (
        AdminAuthError,
    )
    from evergarden.auth.admin_session import (
        credential_document as build,
    )

    try:
        return build(username, password)
    except AdminAuthError as exc:
        raise SetupError(str(exc)) from exc


def render_env(template: str, values: dict[str, str]) -> str:
    """Fill ``KEY=value`` lines of a template, keeping comments and order.

    A commented ``#KEY=`` line is activated when a value is supplied; keys the
    template does not contain are appended at the end.
    """
    remaining = dict(values)
    lines = []
    for line in template.splitlines():
        match = re.fullmatch(r"(#?)([A-Z][A-Z0-9_]*)=(.*)", line)
        if match and match.group(2) in remaining:
            key = match.group(2)
            lines.append(f"{key}={remaining.pop(key)}")
        else:
            lines.append(line)
    if remaining:
        lines.append("")
        lines.extend(f"{key}={value}" for key, value in remaining.items())
    return "\n".join(lines).rstrip("\n") + "\n"


# --- the setup ----------------------------------------------------------------


class Setup:
    def __init__(self, args: argparse.Namespace) -> None:
        self.root: Path = args.root.resolve()
        self.local = self.root / ".local"
        self.run = self.local / "run"
        self.data = self.local / "data"
        self.args = args
        self.created: list[str] = []
        self.kept: list[str] = []
        self.admin_password: str | None = None
        self.renewed = False
        self.trusted_proxies: str | None = None
        self.real_ip_written: str | None = None

    def note(self, path: Path, created: bool) -> None:
        (self.created if created else self.kept).append(str(path.relative_to(self.root)))

    def secret(self, name: str, factory, *, mode: int = 0o600) -> str:
        path = self.run / name
        if existing_regular(path):
            self.note(path, False)
            return read_private(path)
        value = factory()
        write_new(path, value + "\n", mode=mode)
        self.note(path, True)
        return value

    def directories(self) -> None:
        for path in (
            self.local,
            self.run,
            self.run / "mail-config",
            self.run / "mcp-api-keys",
            self.data,
            self.data / "archive",
            self.data / "secrets",
            self.data / "reports",
            self.data / "recovery",
        ):
            private_directory(path)

    def database(self) -> None:
        password = self.secret("postgres_password", lambda: secrets.token_urlsafe(32), mode=0o640)
        pgpass = self.run / "pgpass"
        line = f"postgres:5432:evergarden:evergarden:{password}"
        if existing_regular(pgpass):
            if read_private(pgpass) != line:
                print(
                    "warning: .local/run/pgpass does not match postgres_password; left unchanged",
                    file=sys.stderr,
                )
            self.note(pgpass, False)
        else:
            write_new(pgpass, line + "\n")
            self.note(pgpass, True)

    def credential_key(self) -> None:
        path = self.run / "credential_store_key"
        store = self.data / "secrets" / "credentials.db"
        if not existing_regular(path) and store.exists():
            raise SetupError(
                "the credential store exists but its key .local/run/credential_store_key is "
                "missing; restore the key from backup instead of generating a new one"
            )
        self.secret(
            "credential_store_key",
            lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        )

    def admin(self) -> None:
        self.secret("admin_session_key", lambda: secrets.token_urlsafe(32))
        path = self.run / "admin_credentials.json"
        if existing_regular(path):
            self.note(path, False)
            return
        password = secrets.token_urlsafe(18)
        document = credential_document(self.args.admin_user, password)
        write_new(path, json.dumps(document, separators=(",", ":")) + "\n")
        self.note(path, True)
        self.admin_password = password

    def mail_ui_grant(self, mcp_resource: str) -> None:
        token_path = self.run / "mail_ui_mcp_token"
        registry_path = self.run / "compatibility_tokens.json"
        have_token = existing_regular(token_path)
        have_registry = existing_regular(registry_path)
        if have_token and have_registry:
            self.note(token_path, False)
            self.note(registry_path, False)
            return
        if have_token != have_registry:
            raise SetupError(
                "only one of .local/run/mail_ui_mcp_token and compatibility_tokens.json "
                "exists; remove the other one so setup can issue a matching pair"
            )
        token = secrets.token_urlsafe(48)
        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=MAIL_UI_TOKEN_DAYS)  # noqa: UP017
        registry = {
            "tokens": [
                {
                    "sha256": hashlib.sha256(token.encode()).hexdigest(),
                    "client_id": "mail-ui",
                    "subject": "local:mail-ui",
                    "audience": [mcp_resource],
                    "scopes": list(MAIL_UI_SCOPES),
                    "expires_at": expires.isoformat(timespec="seconds"),
                }
            ]
        }
        write_new(registry_path, json.dumps(registry, separators=(",", ":")) + "\n")
        write_new(token_path, token + "\n")
        self.note(registry_path, True)
        self.note(token_path, True)

    def mail_ui_grant_expiry(self, *, renew: bool) -> str | None:
        """Return the mail UI grant's expiry, extending it first when asked."""
        token_path = self.run / "mail_ui_mcp_token"
        registry_path = self.run / "compatibility_tokens.json"
        if not (existing_regular(token_path) and existing_regular(registry_path)):
            return None
        token = read_private(token_path)
        document = json.loads(read_private(registry_path))
        digest = hashlib.sha256(token.encode()).hexdigest()
        entries = [
            item for item in document.get("tokens", []) if item.get("client_id") == "mail-ui"
        ]
        if len(entries) != 1 or entries[0].get("sha256") != digest:
            if renew:
                raise SetupError(
                    "compatibility_tokens.json has no single mail-ui entry matching "
                    ".local/run/mail_ui_mcp_token; cannot renew it"
                )
            return None
        if renew:
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=MAIL_UI_TOKEN_DAYS)  # noqa: UP017
            entries[0]["expires_at"] = expires.isoformat(timespec="seconds")
            replace_private(registry_path, json.dumps(document, separators=(",", ":")) + "\n")
            self.renewed = True
        return str(entries[0].get("expires_at"))

    def accounts(self) -> None:
        path = self.run / "mail-config" / "mail_accounts.json"
        if existing_regular(path):
            self.note(path, False)
            return
        write_new(path, json.dumps({"schema_version": 1, "accounts": []}) + "\n")
        self.note(path, True)

    def runtime_env(self, origin: str, host_id: str) -> None:
        path = self.run / "runtime.env"
        if existing_regular(path):
            self.note(path, False)
            return
        template = (REPO_ROOT / "runtime.env.example").read_text(encoding="utf-8")
        values = {
            "EVERGARDEN_HOST_ID": host_id,
            "EVERGARDEN_WRITER_EPOCH": "1",
            # A fresh install never writes to a provider until the operator
            # flips the documented switch.
            "EVERGARDEN_SIDE_EFFECTS_ENABLED": "false",
            "EVERGARDEN_TRASH_ACTIONS_ENABLED": "false",
            "EVERGARDEN_MCP_RESOURCE": f"{origin}/mcp",
            "EVERGARDEN_MAIL_UI_APPROVAL_URL": origin,
            "EVERGARDEN_ADMIN_SECURE_COOKIES": "false" if is_loopback_http(origin) else "true",
            "EVERGARDEN_MICROSOFT_OAUTH_REDIRECT_URI": f"{origin}/oauth/callback/microsoft",
            "EVERGARDEN_GOOGLE_OAUTH_REDIRECT_URI": f"{origin}/oauth/callback/google",
        }
        write_new(path, render_env(template, values))
        self.note(path, True)

    def compose_env(self, http_port: int) -> None:
        path = self.root / ".env"
        if existing_regular(path):
            self.note(path, False)
            return
        template = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        profiles = "" if self.args.no_scheduler else "scheduler"
        values = {
            "EVERGARDEN_COMPOSE_PROJECT": self.args.project,
            "EVERGARDEN_UID": str(os.getuid()),
            "EVERGARDEN_GID": str(os.getgid()),
            "COMPOSE_PROFILES": profiles,
            "EVERGARDEN_HTTP_PORT": str(http_port),
            "EVERGARDEN_GATEWAY_REAL_IP": self.args.real_ip or "direct",
        }
        if self.trusted_proxies is not None:
            values["EVERGARDEN_GATEWAY_TRUSTED_PROXIES"] = self.trusted_proxies
        for key, port in (
            ("EVERGARDEN_MCP_PORT", self.args.mcp_port),
            ("EVERGARDEN_APPROVAL_PORT", self.args.approval_port),
        ):
            if port is not None:
                values[key] = str(port)
        write_new(path, render_env(template, values), private_parent=False)
        self.note(path, True)
        self.real_ip_written = values["EVERGARDEN_GATEWAY_REAL_IP"]

    def existing_origin(self) -> str | None:
        """The origin an earlier run recorded, so a re-run reports it unchanged."""
        path = self.run / "runtime.env"
        if not path.is_file() or path.is_symlink():
            return None
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("EVERGARDEN_MAIL_UI_APPROVAL_URL="):
                return line.split("=", 1)[1].strip() or None
        return None

    def execute(self) -> int:
        if not (self.root / "docker-compose.yaml").is_file():
            raise SetupError(f"{self.root} does not contain docker-compose.yaml")
        if not PROJECT_PATTERN.fullmatch(self.args.project):
            raise SetupError("project name must be lowercase letters, digits, '_' or '-'")
        # A neutral default, the same as the code default and runtime.env.example,
        # so the machine's host name never ends up in config or health output.
        host_id = self.args.host_id or DEFAULT_HOST_ID
        if not HOST_ID_PATTERN.fullmatch(host_id) or host_id == "none":
            raise SetupError("host id must be 1-63 letters, digits, '.', '_' or '-'")
        for port in (self.args.http_port, self.args.mcp_port, self.args.approval_port):
            if port is not None and not 1 <= port <= 65535:
                raise SetupError("ports must be 1-65535")
        http_port = self.args.http_port
        origin = normalize_origin(
            self.args.public_origin or f"http://127.0.0.1:{http_port or DEFAULT_HTTP_PORT}"
        )
        origin_port = urlsplit(origin).port
        if is_loopback_http(origin):
            if http_port is not None and origin_port not in {None, http_port}:
                raise SetupError("--http-port and the loopback --public-origin port differ")
            http_port = origin_port or 80
        http_port = http_port or DEFAULT_HTTP_PORT
        if self.args.trusted_proxies is not None:
            if self.args.real_ip not in {"proxy", "cloudflare"}:
                raise SetupError("--trusted-proxies needs --real-ip proxy or --real-ip cloudflare")
            self.trusted_proxies = normalize_trusted_proxies(self.args.trusted_proxies)

        previous = self.existing_origin()
        if self.local.exists() or self.local.is_symlink():
            if self.local.is_symlink():
                raise SetupError(f"{self.local} must not be a symlink")
            require_own(self.local)
        self.directories()
        self.database()
        self.credential_key()
        self.admin()
        self.mail_ui_grant(f"{previous or origin}/mcp")
        grant_expiry = self.mail_ui_grant_expiry(renew=self.args.renew_mail_ui_grant)
        self.accounts()
        self.runtime_env(origin, host_id)
        self.compose_env(http_port)
        self.report(previous or origin, previous is not None and previous != origin, grant_expiry)
        return 0

    def report(self, origin: str, origin_kept: bool, grant_expiry: str | None = None) -> None:
        if self.created:
            print("created:")
            for item in self.created:
                print(f"  {item}")
        if self.kept:
            print("kept (already present, not modified):")
            for item in self.kept:
                print(f"  {item}")
        if origin_kept:
            print(
                f"note: the existing runtime.env keeps origin {origin}; edit "
                "EVERGARDEN_MCP_RESOURCE, EVERGARDEN_MAIL_UI_APPROVAL_URL, the redirect URIs and "
                "EVERGARDEN_ADMIN_SECURE_COOKIES there to change it"
            )
        if self.real_ip_written == "direct" and not is_loopback_http(origin):
            print(
                "note: the gateway uses client-address mode direct, so behind a reverse proxy "
                "every client shares one login throttle bucket. Set "
                "EVERGARDEN_GATEWAY_REAL_IP=proxy (or cloudflare) in .env; see "
                "docs/configuration.md"
            )
        elif self.args.real_ip and self.real_ip_written is None:
            print(
                "note: .env already exists and was not modified; set "
                f"EVERGARDEN_GATEWAY_REAL_IP={self.args.real_ip} there yourself"
            )
        if self.admin_password is not None:
            print()
            print("Administrator login (shown only this once; store it in a password manager):")
            print(f"  username: {self.args.admin_user}")
            print(f"  password: {self.admin_password}")
            print("Reset it later with deploy/scripts/manage_admin_credentials.py.")
        print()
        print("Next steps:")
        print("  1. docker compose up -d --build")
        print(f"  2. open {origin} and sign in")
        print(
            '  3. add a mailbox under "Manage mailboxes"; for a password (IMAP) mailbox store its'
        )
        print("     app password, which the web form never accepts:")
        print(
            "       docker compose exec approval-ui evergarden-provider-credential "
            "set-password --account <alias>"
        )
        print("  4. docker compose restart mcp approval-ui mail-ui   (after every mailbox change)")
        print('  5. sync from the mail UI, then create an API key under "Connect an MCP agent"')
        if grant_expiry:
            print()
            if self.renewed:
                print(f"The mail UI's MCP grant was renewed until {grant_expiry}.")
                print("Apply it with: docker compose restart mcp")
            else:
                print(f"The mail UI's MCP grant expires {grant_expiry}. Before then run")
                print("  ./deploy/setup --renew-mail-ui-grant && docker compose restart mcp")
        print(
            "Provider writes (send, move, mark) are OFF. To enable them set "
            "EVERGARDEN_SIDE_EFFECTS_ENABLED=true in .local/run/runtime.env and run "
            "docker compose up -d; every write still needs your approval."
        )
        print(
            "Keep EVERGARDEN_HOST_ID and .local/run/credential_store_key unchanged and backed "
            "up: stored mailbox credentials are encrypted with both."
        )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else None,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--root", type=Path, default=REPO_ROOT, help="deployment root (default: this clone)"
    )
    parser.add_argument(
        "--public-origin",
        help=(
            "origin browsers and MCP clients use, e.g. https://mail.example.com behind a "
            "reverse proxy (Secure cookies); default http://127.0.0.1:<http-port>"
        ),
    )
    parser.add_argument("--http-port", type=int, help="gateway host port (default 8788)")
    parser.add_argument("--mcp-port", type=int, help="direct MCP host port (default 8420)")
    parser.add_argument("--approval-port", type=int, help="approval UI host port (default 8421)")
    parser.add_argument(
        "--real-ip",
        choices=REAL_IP_MODES,
        help=(
            "where the gateway takes the client address from: direct (default, nothing in "
            "front), proxy (a reverse proxy's X-Forwarded-For) or cloudflare (proxy plus "
            "CF-Connecting-IP from Cloudflare edges)"
        ),
    )
    parser.add_argument(
        "--trusted-proxies",
        metavar="CIDRS",
        help=(
            "comma-separated addresses/CIDRs of the reverse proxies trusted in proxy and "
            "cloudflare mode, or none (default: loopback, RFC 1918 and fc00::/7)"
        ),
    )
    parser.add_argument(
        "--host-id",
        help=(
            "stable deployment id bound into credential encryption "
            f"(default: {DEFAULT_HOST_ID}); never change it once mailboxes are stored"
        ),
    )
    parser.add_argument("--admin-user", default="admin", help="administrator username")
    parser.add_argument(
        "--project", default="evergarden", help="compose project name (default: evergarden)"
    )
    parser.add_argument(
        "--no-scheduler",
        action="store_true",
        help="leave the in-stack scheduler profile off (use a host timer instead)",
    )
    parser.add_argument(
        "--renew-mail-ui-grant",
        action="store_true",
        help=f"extend the mail UI's own MCP grant to {MAIL_UI_TOKEN_DAYS} days from now",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="never prompt; use the options and defaults as given",
    )
    return parser.parse_args(argv)


def interactive(args: argparse.Namespace) -> None:
    """Ask for the two choices that matter when run from a terminal."""
    default = f"http://127.0.0.1:{args.http_port or DEFAULT_HTTP_PORT}"
    if args.public_origin is None:
        answer = input(
            f"Public origin [{default}] (https://... when behind a reverse proxy): "
        ).strip()
        args.public_origin = answer or None
    if args.real_ip is None and (args.public_origin or "").startswith("https://"):
        answer = input(
            "What sits in front of the gateway: a reverse proxy (proxy) or Cloudflare, "
            "directly or through a proxy (cloudflare)? [proxy]: "
        ).strip()
        args.real_ip = answer or "proxy"
        if args.real_ip not in REAL_IP_MODES:
            raise SetupError(f"client-address mode must be one of {', '.join(REAL_IP_MODES)}")
    answer = input(f"Administrator username [{args.admin_user}]: ").strip()
    if answer:
        args.admin_user = answer


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if (
            not args.non_interactive
            and sys.stdin.isatty()
            and not ((args.root.resolve() / ".local" / "run" / "runtime.env").exists())
        ):
            interactive(args)
        return Setup(args).execute()
    except SetupError as exc:
        print(f"setup failed: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"setup failed: {exc}. Check that you own the deployment root and its .local "
            "directory (Docker creates root-owned paths when the stack starts before setup).",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
