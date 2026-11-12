from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Intent kinds that may skip the human approval surface. TRASH is deliberately
# absent and must stay absent: it is the only irreversible-shaped intent.
AUTO_APPROVABLE_KINDS = ("send", "archive", "move", "mark")
UIDPLUS_ALIAS_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}")
# A host identifier names this deployment in writer control, job leases and
# the authenticated encryption context of stored credentials. The database
# constraint on runtime_control.active_writer (migration 007) uses the same
# pattern, so any accepted id can also be recorded as the active writer.
HOST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
# Reserved active-writer value meaning that no host may perform writes.
NO_WRITER = "none"
DEFAULT_HOST_ID = "default"
# Host names that may be served over plain HTTP: a browser or MCP client on the
# same machine talks to the published loopback port without TLS.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def is_https_or_loopback_http(value: str) -> bool:
    """Accept an HTTPS URL, or plain HTTP only when it names a loopback host."""
    parts = urlsplit(value)
    if not parts.netloc or parts.username or parts.password or parts.fragment:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS)


def parse_auto_approve(value: str) -> frozenset[str]:
    """Normalize an EVERGARDEN_AUTO_APPROVE value into intent kinds."""
    items = [item.strip().casefold() for item in value.split(",") if item.strip()]
    if not items:
        return frozenset()
    if "all" in items:
        if len(items) > 1:
            raise ValueError("auto-approve 'all' cannot be combined with other intent kinds")
        return frozenset(AUTO_APPROVABLE_KINDS)
    if "trash" in items:
        raise ValueError("auto-approve can never include trash; it requires a human approval")
    unknown = sorted(set(items) - set(AUTO_APPROVABLE_KINDS))
    if unknown:
        raise ValueError(f"unknown auto-approve intent kinds: {', '.join(unknown)}")
    return frozenset(items)


class Settings(BaseSettings):
    """Runtime settings with fail-closed defaults.

    A fresh install is read-only: it syncs and archives mail, prepares drafts
    and records human approvals, but performs no provider write (send, move,
    mark, Trash). ``EVERGARDEN_SIDE_EFFECTS_ENABLED=true`` is the single switch
    that enables writes. Even then every write needs a human approval unless
    its kind is listed in ``EVERGARDEN_AUTO_APPROVE``, and Trash never skips
    the human gate.

    ``host_id`` is a stable name for this deployment. It is bound into the
    encryption context of stored credentials and approvals, so it must not
    change once credentials exist. ``active_writer`` names the one host that
    may write; it defaults to ``host_id`` (a single-host deployment) and may be
    set to ``none`` to forbid writes from every host. ``writer_epoch`` must
    match the database writer control row; raising it fences out any older
    process still running with the previous value.
    """

    model_config = SettingsConfigDict(
        env_prefix="EVERGARDEN_",
        env_file=None,
        # Docker env files render an unset optional value as "KEY="; treat
        # it as absent so the code default applies instead of failing to
        # parse an empty URL or turning an empty path into ".".
        env_ignore_empty=True,
        case_sensitive=False,
        extra="ignore",
    )

    host_id: str = DEFAULT_HOST_ID
    active_writer: str | None = None
    writer_epoch: int = Field(default=1, ge=1)
    side_effects_enabled: bool = False
    trash_actions_enabled: bool = False
    # Human approvals of every enabled kind are executed by the MCP dispatcher.
    approval_dispatch_enabled: bool = False
    # Mailboxes the dispatcher runs at the same time. Each one holds one IMAP
    # connection and at most one message body, which bounds memory use.
    approval_dispatch_parallel: int = Field(default=4, ge=1, le=8)
    # Comma-separated account aliases allowed to move mail with UID COPY,
    # STORE \Deleted and UID EXPUNGE when the provider lacks IMAP MOVE.
    uidplus_move_accounts: str = ""
    # Comma-separated intent kinds whose approval is issued automatically at
    # preparation time instead of by a human on the approval surface. Accepts
    # "all" as shorthand for every auto-approvable kind. "trash" is always
    # refused: a deletion-shaped action keeps its human gate permanently.
    auto_approve: str = ""
    # IANA timezone in which job schedules (cron expressions) are evaluated
    # and in which scheduled slot identifiers are written.
    schedule_timezone: str = "UTC"

    database_url: str = "postgresql://evergarden@postgres:5432/evergarden"
    archive_dir: Path = Path("/data/archive")
    report_dir: Path = Path("/data/reports")
    credential_db: Path = Path("/data/secrets/credentials.db")
    credential_key_file: Path = Path("/run/secrets/credential_store_key")
    account_config_file: Path | None = None
    thunderbird_bridge_accounts: str = ""
    thunderbird_bridge_clients_file: Path = Path("/run/mail-config/thunderbird-bridge-clients.json")

    # Public URL of the MCP endpoint. It is the audience of every bearer token
    # and the URL shown in client setup instructions. HTTPS, or loopback HTTP
    # for a single-machine install (http://127.0.0.1:8788/mcp).
    mcp_resource: AnyHttpUrl = "https://evergarden.example.invalid/mcp"
    # Authorization server advertised in the protected-resource metadata. Only
    # used by JWT/introspection verification; API keys and compatibility
    # tokens do not need it, so the placeholder is harmless without them.
    oauth_issuer: AnyHttpUrl = "https://auth.example.invalid"
    # JWT verification must be enabled only with a discovered and validated
    # JWKS URI, never a guessed issuer-relative path.
    oauth_jwks_url: AnyHttpUrl | None = None
    oauth_introspection_url: AnyHttpUrl | None = None
    oauth_introspection_client_id: str | None = None
    oauth_introspection_client_secret_file: Path | None = None
    compatibility_token_file: Path | None = None
    # Self-service bearer tokens issued from the mail UI. Distinct from the
    # SOPS-provisioned compatibility registry: this one is mutable at runtime.
    mcp_api_keys_file: Path | None = None

    microsoft_oauth_client_id: str = "replace-with-public-client-id"
    microsoft_oauth_tenant: str = "common"
    microsoft_oauth_redirect_uri: str = "http://127.0.0.1:8788/oauth/callback/microsoft"
    google_oauth_redirect_uri: str = "http://127.0.0.1:8788/oauth/callback/google"

    # --- Microsoft OAuth flow and optional MFA auto-login --------------------
    # Every deployment registers its own Microsoft Entra app and sets
    # microsoft_oauth_client_id; the shipped placeholder is rejected at sign-in.
    microsoft_oauth_flow: Literal["authorization_code", "device_code"] = "authorization_code"
    # The Entra app's display name as Microsoft shows it on sign-in pages.
    # Empty: the UI shows generic text and MFA auto-login will not approve
    # Microsoft's "sign in on another device" prompt.
    microsoft_oauth_app_name: str = ""
    # MFA auto-login (compose profile mfa-autologin) also needs this switch.
    mfa_autologin_enabled: bool = False
    # Comma-separated federated identity-provider hosts (for example an
    # organisation's ADFS) the sign-in browser may visit besides Microsoft's own.
    mfa_extra_allowed_hosts: str = ""
    # Browser locale for the sign-in pages; their text is matched in English.
    mfa_browser_locale: str = "en-US"

    @property
    def mfa_extra_allowed_host_list(self) -> tuple[str, ...]:
        return tuple(
            item.strip().casefold()
            for item in self.mfa_extra_allowed_hosts.split(",")
            if item.strip()
        )

    @model_validator(mode="after")
    def validate_identity_settings(self) -> Settings:
        name = self.microsoft_oauth_app_name
        if len(name) > 120 or any(not character.isprintable() for character in name):
            raise ValueError(
                "Microsoft OAuth app name must be printable and at most 120 characters"
            )
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        for host in self.mfa_extra_allowed_host_list:
            if not re.fullmatch(rf"(?:{label}\.)+{label}", host):
                raise ValueError(f"MFA allowed host is not a hostname: {host}")
        if not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}", self.mfa_browser_locale):
            raise ValueError("MFA browser locale must be a language tag such as en-US")
        return self

    # --- end of Microsoft OAuth flow and MFA auto-login settings --------------

    admin_credential_file: Path | None = None
    admin_session_key_file: Path | None = None
    admin_session_ttl_seconds: int = Field(default=7 * 24 * 60 * 60, ge=300, le=30 * 24 * 60 * 60)
    # Logout records a per-administrator "signed out before" time here, which
    # every browser surface checks. The mail UI writes it, the approval UI only
    # reads it; a missing file simply means nobody has logged out yet.
    admin_session_revocation_file: Path | None = Path(
        "/run/mail-config/admin_session_revocations.json"
    )
    # Keyed by the client address the gateway resolves. In its default direct
    # mode behind a reverse proxy all remote clients share one bucket (see
    # EVERGARDEN_GATEWAY_REAL_IP); 15 keeps a third party's typos from locking
    # out the one admin even then.
    admin_login_max_failures: int = Field(default=15, ge=3, le=20)
    admin_login_window_seconds: int = Field(default=15 * 60, ge=60, le=60 * 60)
    admin_secure_cookies: bool = True
    # Review window of a draft awaiting human approval.
    approval_draft_lifetime_hours: int = Field(default=6, ge=1, le=72)
    approval_ui_enabled: bool = False
    oauth_callback_enabled: bool = False
    mail_ui_enabled: bool = False
    mail_ui_mcp_url: str = "http://mcp:8000/mcp"
    mail_ui_mcp_token_file: Path | None = None
    mail_ui_approval_url: str = "http://127.0.0.1:8788"
    mail_ui_account_admin_enabled: bool = False
    mail_ui_api_keys_enabled: bool = False
    log_level: str = "INFO"

    @model_validator(mode="before")
    @classmethod
    def _blank_host_id_is_an_error(cls, data: object) -> object:
        # env_ignore_empty turns "EVERGARDEN_HOST_ID=" into "unset", which would
        # silently fall back to the default id. The host id is bound into the
        # credential encryption context, so a blanked line must fail instead.
        if isinstance(data, dict) and "host_id" not in data:
            for key, value in os.environ.items():
                if key.upper() == "EVERGARDEN_HOST_ID" and not value.strip():
                    raise ValueError(
                        "EVERGARDEN_HOST_ID is set but empty; restore this deployment's host id"
                    )
        return data

    @field_validator("active_writer", mode="before")
    @classmethod
    def _blank_writer_means_default(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def enforce_safety_boundary(self) -> Settings:
        if not HOST_ID_PATTERN.fullmatch(self.host_id) or self.host_id == NO_WRITER:
            raise ValueError(
                "host id must be 1-63 letters, digits, '.', '_' or '-' and must not be 'none'"
            )
        if self.active_writer is None:
            self.active_writer = self.host_id
        if not HOST_ID_PATTERN.fullmatch(self.active_writer):
            raise ValueError("active writer must be a host id or 'none'")
        if self.side_effects_enabled and self.active_writer != self.host_id:
            raise ValueError(
                "side effects can only be enabled on the active writer host; "
                "set EVERGARDEN_ACTIVE_WRITER to this host id or leave it unset"
            )
        try:
            ZoneInfo(self.schedule_timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("schedule timezone must be an IANA timezone name") from exc
        if not is_https_or_loopback_http(str(self.mcp_resource)) or not (
            is_https_or_loopback_http(str(self.oauth_issuer))
        ):
            raise ValueError("MCP resource and OAuth issuer must use HTTPS or loopback HTTP")
        introspection_fields = (
            self.oauth_introspection_url,
            self.oauth_introspection_client_id,
            self.oauth_introspection_client_secret_file,
        )
        if any(introspection_fields) and not all(introspection_fields):
            raise ValueError("OAuth introspection requires endpoint, client id, and secret file")
        if (
            not self.microsoft_oauth_client_id
            or len(self.microsoft_oauth_client_id) > 200
            or any(character.isspace() for character in self.microsoft_oauth_client_id)
        ):
            raise ValueError("Microsoft OAuth client id must be a non-empty token")
        if (
            not self.microsoft_oauth_tenant
            or len(self.microsoft_oauth_tenant) > 100
            or any(character in self.microsoft_oauth_tenant for character in "/?#")
        ):
            raise ValueError("Microsoft OAuth tenant is malformed")
        for provider, uri in (
            ("Microsoft", self.microsoft_oauth_redirect_uri),
            ("Google", self.google_oauth_redirect_uri),
        ):
            redirect = urlsplit(uri)
            loopback = redirect.hostname in LOOPBACK_HOSTS
            if (
                not redirect.netloc
                or redirect.username
                or redirect.password
                or redirect.query
                or redirect.fragment
                or (redirect.scheme != "https" and not (redirect.scheme == "http" and loopback))
            ):
                raise ValueError(
                    f"{provider} OAuth redirect must be HTTPS or an exact loopback HTTP URL"
                )
        ui_mcp = urlsplit(self.mail_ui_mcp_url)
        if (
            ui_mcp.path != "/mcp"
            or ui_mcp.query
            or ui_mcp.fragment
            or ui_mcp.username
            or ui_mcp.password
            or not ui_mcp.netloc
            or (
                ui_mcp.scheme != "https"
                and not (
                    ui_mcp.scheme == "http"
                    and (ui_mcp.hostname == "mcp" or ui_mcp.hostname in LOOPBACK_HOSTS)
                )
            )
        ):
            raise ValueError("mail UI MCP URL must be HTTPS or an internal/loopback HTTP /mcp URL")
        approval = urlsplit(self.mail_ui_approval_url)
        if (
            approval.scheme not in {"http", "https"}
            or not approval.netloc
            or approval.username
            or approval.password
            or approval.query
            or approval.fragment
            or (approval.scheme == "http" and approval.hostname not in LOOPBACK_HOSTS)
        ):
            raise ValueError("mail UI approval URL must be HTTPS or exact loopback HTTP")
        # The cookies exist only while a browser surface is enabled.
        if (
            not self.admin_secure_cookies
            and (self.mail_ui_enabled or self.approval_ui_enabled)
            and not (approval.scheme == "http" and approval.hostname in LOOPBACK_HOSTS)
        ):
            raise ValueError(
                "non-Secure admin cookies are only allowed for a loopback http:// mail UI "
                "approval URL; set EVERGARDEN_ADMIN_SECURE_COOKIES=true for an HTTPS origin"
            )
        if self.mail_ui_enabled and self.mail_ui_mcp_token_file is None:
            raise ValueError("enabled mail UI requires a private MCP token file")
        if self.mail_ui_enabled and self.admin_credential_file is None:
            raise ValueError("enabled mail UI requires a private admin credential file")
        if self.mail_ui_account_admin_enabled and (
            not self.mail_ui_enabled or self.account_config_file is None
        ):
            raise ValueError(
                "mail UI account administration requires UI and private account config"
            )
        if self.mail_ui_api_keys_enabled and (
            not self.mail_ui_enabled or self.mcp_api_keys_file is None
        ):
            raise ValueError("mail UI API key issuance requires UI and a private key registry")
        if (
            self.approval_ui_enabled or self.oauth_callback_enabled or self.mail_ui_enabled
        ) and self.admin_session_key_file is None:
            raise ValueError("enabled human web surfaces require a private admin session key")
        # Raises on an unknown or forbidden kind so a typo fails startup rather
        # than silently reinstating a gate the operator meant to remove.
        parse_auto_approve(self.auto_approve)
        return self

    @property
    def oauth_bearer_enabled(self) -> bool:
        """True when MCP can verify OAuth access tokens (JWKS or introspection).

        Without either, the issuer is never trusted, so it must not be advertised
        to MCP clients either: API keys are then the only way in.
        """
        return bool(self.oauth_jwks_url or self.oauth_introspection_url)

    @property
    def mode(self) -> Literal["read-only", "production"]:
        """Derived runtime mode: "production" only when this host may write."""
        if self.side_effects_enabled and self.is_active_writer:
            return "production"
        return "read-only"

    @property
    def is_active_writer(self) -> bool:
        return self.active_writer == self.host_id

    @property
    def auto_approve_kinds(self) -> frozenset[str]:
        return parse_auto_approve(self.auto_approve)

    @property
    def thunderbird_bridge_account_set(self) -> frozenset[str]:
        # Account aliases are casefolded on load; a mixed-case entry here
        # would otherwise silently match nothing and drop the receive-only
        # restriction for a bridge account that is also natively enabled.
        return frozenset(
            item.strip().casefold()
            for item in self.thunderbird_bridge_accounts.split(",")
            if item.strip()
        )

    @property
    def uidplus_move_account_set(self) -> frozenset[str]:
        aliases = {
            item.strip().casefold()
            for item in self.uidplus_move_accounts.split(",")
            if item.strip()
        }
        if any(not UIDPLUS_ALIAS_PATTERN.fullmatch(alias) for alias in aliases):
            raise ValueError("EVERGARDEN_UIDPLUS_MOVE_ACCOUNTS contains a malformed alias")
        return frozenset(aliases)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    if settings.account_config_file is not None:
        from evergarden.runtime_settings import RuntimeSettingsManager

        return RuntimeSettingsManager(settings).configured()
    return settings
