"""IMAP connection and authentication, including every provider quirk.

This module is the only place that knows how to open and authenticate an
IMAP connection. Anything provider-specific about getting a usable
mailbox session — the Outlook.com transient-rejection lottery, the
refresh-once-on-rejection rule for Microsoft tokens — lives here, not in
sync or action code. A future non-IMAP provider (e.g. Microsoft Graph)
replaces this module behind the same call sites.
"""

from __future__ import annotations

import contextlib
import imaplib
import logging
import ssl
import time
from typing import Protocol

from evergarden.auth.credential_store import CredentialStore
from evergarden.mail.models import AccountConfig
from evergarden.mail.xoauth2 import xoauth2_response

logger = logging.getLogger(__name__)


class OAuthAccessToken(Protocol):
    def __call__(self, account: AccountConfig, *, force_refresh: bool = False) -> str: ...


class ImapFactory(Protocol):
    def __call__(self, host: str, port: int, timeout: int = 30): ...


class UnsupportedAuthKind(ValueError):
    """The account's auth_kind has no IMAP authentication strategy."""


# Exchange Online answers AUTHENTICATE with this NO when the token is valid
# but no mailbox session is granted. For personal Outlook.com accounts this is
# a long-standing Microsoft fault: each new connection succeeds independently
# with roughly one-in-five odds (measured 2026-10-02), regardless of delay or
# frontend, and the server drops a connection re-authenticated in place. A
# fresh token cannot help; only new connections can. Waiting longer between
# attempts does not raise the odds, so an interactive caller spends its
# ~30-second budget on connection count, not on backoff: twelve fresh
# connections leave roughly a 7% chance of a fully failed call at the
# measured one-in-five rate, versus 26% with six.
_TRANSIENT_AUTH_REJECTIONS = ("authenticated but not connected",)
SYNC_TRANSIENT_AUTH_RETRY_SECONDS = (5, *(10,) * 10)
INTERACTIVE_TRANSIENT_AUTH_RETRY_SECONDS = (1,) * 11


def is_transient_auth_rejection(exc: BaseException) -> bool:
    return (
        isinstance(exc, imaplib.IMAP4.error)
        and not isinstance(exc, imaplib.IMAP4.abort)
        and any(marker in str(exc).lower() for marker in _TRANSIENT_AUTH_REJECTIONS)
    )


class ImapConnector:
    """Opens fresh, authenticated IMAP connections.

    A connection whose AUTHENTICATE was rejected is never reused or
    re-authenticated; the retry strategies below always start over with a
    new connection.
    """

    def __init__(
        self,
        *,
        imap_factory: ImapFactory,
        oauth_access_token: OAuthAccessToken,
        credentials: CredentialStore,
        timeout: int = 30,
    ):
        self.imap_factory = imap_factory
        self.oauth_access_token = oauth_access_token
        self.credentials = credentials
        self.timeout = timeout

    def authenticate_once(self, account: AccountConfig, *, force_refresh: bool):
        client = self.imap_factory(account.imap_host, account.imap_port, timeout=self.timeout)
        try:
            if account.auth_kind == "oauth2":
                token = (
                    self.oauth_access_token(account, force_refresh=True)
                    if force_refresh
                    else self.oauth_access_token(account)
                )
                client.authenticate("XOAUTH2", xoauth2_response(account.address, token))
            elif account.auth_kind == "password":
                record = self.credentials.get(account.credential_record)
                client.login(account.address, str(record["password"]))
            else:
                raise UnsupportedAuthKind(f"unsupported auth kind for {account.alias}")
        except Exception:
            with contextlib.suppress(Exception):
                client.logout()
            raise
        return client

    def _authenticate_with_refresh(self, account: AccountConfig):
        try:
            return self.authenticate_once(account, force_refresh=False)
        except imaplib.IMAP4.abort:
            raise
        except imaplib.IMAP4.error as exc:
            if account.auth_kind != "oauth2" or is_transient_auth_rejection(exc):
                raise
            # Microsoft can invalidate a nominally unexpired token. Refresh
            # once after an explicit authentication rejection, never after a
            # mailbox command whose provider outcome could be ambiguous.
            return self.authenticate_once(account, force_refresh=True)

    def authenticate_interactive(self, account: AccountConfig):
        """Authenticate within an interactive caller's ~30-second budget.

        AUTHENTICATE has no mailbox side effect, so a transient provider
        rejection is safe to retry before any mailbox command is issued.
        Connection-level failures are not retried: an interactive caller
        should see them immediately.
        """
        for delay in (*INTERACTIVE_TRANSIENT_AUTH_RETRY_SECONDS, None):
            try:
                return self._authenticate_with_refresh(account)
            except imaplib.IMAP4.error as exc:
                if delay is None or not is_transient_auth_rejection(exc):
                    raise
                time.sleep(delay)
        raise AssertionError("unreachable authentication retry state")

    def authenticate_background(self, account: AccountConfig):
        """Authenticate with the patient background-sync budget.

        Background sync additionally retries connection-level failures a
        few times, because an hourly slot has nothing better to do, and
        logs each retry so failing slots stay visible.
        """
        connection_failures = 0
        transient_delays = iter(SYNC_TRANSIENT_AUTH_RETRY_SECONDS)
        while True:
            try:
                return self._authenticate_with_refresh(account)
            except ssl.SSLCertVerificationError:
                raise
            except (OSError, ssl.SSLError, imaplib.IMAP4.abort) as exc:
                # OSError covers ConnectionError/TimeoutError and also plain
                # socket faults (DNS gaierror, ENETUNREACH) that the patient
                # background budget is meant to ride out.
                connection_failures += 1
                if connection_failures == 3:
                    raise
                logger.warning(
                    "IMAP connection retry account=%s attempt=%s error_class=%s",
                    account.alias,
                    connection_failures,
                    type(exc).__name__,
                )
                time.sleep(connection_failures)
            except imaplib.IMAP4.error as exc:
                delay = next(transient_delays, None)
                if delay is None or not is_transient_auth_rejection(exc):
                    raise
                logger.warning(
                    "IMAP transient authentication retry account=%s delay=%s",
                    account.alias,
                    delay,
                )
                time.sleep(delay)
