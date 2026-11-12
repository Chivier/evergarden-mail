"""SMTP connection and authentication, mirroring ImapConnector.

Transport setup (SSL or STARTTLS) and authentication live here; outcome
classification for the approval pipeline stays with the executor, because
whether a failure is retryable depends on whether submission started.
"""

from __future__ import annotations

import contextlib
import ssl
from collections.abc import Callable
from typing import Protocol

from evergarden.auth.credential_store import CredentialStore
from evergarden.mail.imap_connector import OAuthAccessToken
from evergarden.mail.models import AccountConfig
from evergarden.mail.xoauth2 import xoauth2_response


class SmtpFactory(Protocol):
    def __call__(self, host: str, port: int, timeout: int = 30, **kwargs): ...


class UnsupportedSmtpMode(ValueError):
    """The account's smtp_mode has no transport strategy."""


class SmtpConnector:
    def __init__(
        self,
        *,
        smtp_factory: SmtpFactory,
        smtp_ssl_factory: SmtpFactory,
        ssl_context_factory: Callable[[], ssl.SSLContext],
        oauth_access_token: OAuthAccessToken,
        credentials: CredentialStore,
        timeout: int = 30,
    ):
        self.smtp_factory = smtp_factory
        self.smtp_ssl_factory = smtp_ssl_factory
        self.ssl_context_factory = ssl_context_factory
        self.oauth_access_token = oauth_access_token
        self.credentials = credentials
        self.timeout = timeout

    def connect(self, account: AccountConfig, *, force_refresh: bool):
        """Open and authenticate an SMTP session; closed again on any failure."""
        smtp = None
        try:
            if account.smtp_mode == "ssl":
                smtp = self.smtp_ssl_factory(
                    account.smtp_host,
                    account.smtp_port,
                    timeout=self.timeout,
                    context=self.ssl_context_factory(),
                )
            elif account.smtp_mode == "starttls":
                smtp = self.smtp_factory(account.smtp_host, account.smtp_port, timeout=self.timeout)
                smtp.ehlo()
                smtp.starttls(context=self.ssl_context_factory())
                smtp.ehlo()
            else:
                raise UnsupportedSmtpMode(f"unsupported smtp mode for {account.alias}")
            if account.auth_kind == "oauth2":
                token = (
                    self.oauth_access_token(account, force_refresh=True)
                    if force_refresh
                    else self.oauth_access_token(account)
                )
                smtp.auth("XOAUTH2", xoauth2_response(account.address, token, as_bytes=False))
            else:
                record = self.credentials.get(account.credential_record)
                smtp.login(account.address, str(record["password"]))
            return smtp
        except Exception:
            if smtp is not None:
                with contextlib.suppress(Exception):
                    smtp.quit()
            raise
