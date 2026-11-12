"""Turn a failed sync's MCP error into a short, per-mailbox summary for the web UI.

``sync_mail`` reports an incomplete sync as JSON (``mail_sync_incomplete`` with
``failed_accounts``). The workbench shows each failed mailbox with a reason
class a person can act on; the provider's own (already redacted) wording stays
available as a secondary detail.
"""

from __future__ import annotations

import json
import re
from typing import Any

from evergarden.audit.redaction import redact_error_detail

SYNC_INCOMPLETE_ERROR = "mail_sync_incomplete"
REASONS = ("dns", "refused", "auth", "timeout", "other")
MAX_ACCOUNTS = 50
MAX_FOLDERS = 10
DETAIL_LIMIT = 300
# The MCP error text is our own JSON; refuse to parse anything implausibly large.
MAX_TEXT = 256 * 1024

_DNS = re.compile(
    r"name or service not known|nodename nor servname|temporary failure in name resolution|"
    r"no address associated with hostname|name resolution|getaddrinfo failed",
    re.IGNORECASE,
)
_REFUSED = re.compile(r"connection refused|errno 111\b|actively refused", re.IGNORECASE)
_TIMEOUT = re.compile(r"timed out|timeout", re.IGNORECASE)
_AUTH = re.compile(
    r"authenticationfailed|authentication failed|authentication unsuccessful|"
    r"authenticate failed|invalid credentials|login failed|logon failure|"
    r"invalid_grant|interaction_required|consent_required|invalid_client|unauthorized_client|"
    r"reauthorization required|username and password not accepted|application-specific password",
    re.IGNORECASE,
)
# OAuthTokenRequestError carries the token endpoint's HTTP status; a 4xx other
# than 429 means the provider rejected the grant or client, so reconnecting is
# the fix. 5xx and 429 are provider-side and stay "other".
_OAUTH_REJECTED = re.compile(r"OAuth token request failed \((4(?!29)\d\d)\)")
_AUTH_CLASSES = frozenset(
    {
        "CredentialNotFound",
        "CredentialDecryptionError",
        "OAuthConfigurationError",
        "MicrosoftConfigurationError",
        "GoogleConfigurationError",
        "GoogleIdentityError",
        "UnsupportedAuthKind",
    }
)
_TIMEOUT_CLASSES = frozenset({"TimeoutError", "timeout", "SSLTimeoutError", "ReadTimeout"})


def classify_sync_failure(error_class: str, detail: str) -> str:
    """Map an exception class name and its detail to one of ``REASONS``."""
    if error_class == "gaierror" or _DNS.search(detail):
        return "dns"
    if error_class == "ConnectionRefusedError" or _REFUSED.search(detail):
        return "refused"
    if error_class in _AUTH_CLASSES or _AUTH.search(detail):
        return "auth"
    if error_class == "OAuthTokenRequestError" and _OAUTH_REJECTED.search(detail):
        return "auth"
    if error_class in _TIMEOUT_CLASSES or _TIMEOUT.search(detail):
        return "timeout"
    return "other"


def _text(value: Any, limit: int) -> str:
    return redact_error_detail(value if isinstance(value, str) else "", limit=limit)


def _summarize_account(item: dict) -> dict[str, Any]:
    error_class = _text(item.get("error_class"), 64)
    detail = _text(item.get("error_detail"), DETAIL_LIMIT)
    raw_folders = item.get("failed_folders") or []
    folders = [folder for folder in raw_folders if isinstance(folder, dict)][:MAX_FOLDERS]
    if folders:
        # The account-level message only counts folders; the first folder
        # failure carries the provider's wording.
        first = folders[0]
        error_class = _text(first.get("error_class"), 64) or error_class
        detail = "; ".join(
            f"{_text(folder.get('folder'), 100)}: {_text(folder.get('error_detail'), 200)}"
            for folder in folders
        )[:DETAIL_LIMIT]
    return {
        "account": _text(item.get("account"), 64),
        "reason": classify_sync_failure(error_class, detail),
        "error_class": error_class,
        "detail": detail,
        "folders": [_text(folder.get("folder"), 100) for folder in folders],
    }


def summarize_sync_incomplete(text: str) -> list[dict[str, Any]] | None:
    """Per-mailbox summaries of a ``mail_sync_incomplete`` error, or ``None``."""
    if not isinstance(text, str) or len(text) > MAX_TEXT or not text.lstrip().startswith("{"):
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    if not isinstance(value, dict) or value.get("error") != SYNC_INCOMPLETE_ERROR:
        return None
    accounts = value.get("failed_accounts")
    if not isinstance(accounts, list):
        return None
    return [_summarize_account(item) for item in accounts[:MAX_ACCOUNTS] if isinstance(item, dict)]
