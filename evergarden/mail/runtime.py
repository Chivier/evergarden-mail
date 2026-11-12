from __future__ import annotations

import datetime as dt
import logging

from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter
from evergarden.audit.redaction import redact_error_detail
from evergarden.auth.credential_store import CredentialNotFound, CredentialStore, read_key_file
from evergarden.auth.google_oauth import GoogleOAuthClient
from evergarden.auth.provider_oauth import MicrosoftOAuthClient, microsoft_registration
from evergarden.config import Settings
from evergarden.mail.actions import MailActionExecutor
from evergarden.mail.models import (
    AccountConfig,
    folder_precedence_by_alias,
    load_account_configs,
)
from evergarden.mail.policy import AccountPolicy
from evergarden.mail.staged_attachments import StagedAttachmentStore
from evergarden.mail.sync import MailboxSyncIncomplete, ReadOnlyMailboxSync

MICROSOFT_REFRESH_MARGIN_SECONDS = 1800

logger = logging.getLogger(__name__)


def _sync_failure(alias: str, exc: Exception) -> dict[str, object]:
    """Describe one account's sync failure without leaking mail or credentials."""
    failure: dict[str, object] = {
        "account": alias,
        "error_class": type(exc).__name__,
        "error_detail": redact_error_detail(exc),
    }
    if isinstance(exc, MailboxSyncIncomplete):
        # The account-level message only counts folders; the provider's own
        # wording lives on each folder failure.
        failure["failed_folders"] = [
            {
                "folder": item["folder"],
                "error_class": item["error_class"],
                "error_detail": item.get("error_detail", ""),
            }
            for item in exc.failures
        ]
    return failure


def _log_sync_failure(failure: dict[str, object]) -> None:
    folders = failure.get("failed_folders")
    detail = (
        "; ".join(
            f"{item['folder']}={item['error_class']}: {item['error_detail']}" for item in folders
        )
        if isinstance(folders, list) and folders
        else failure["error_detail"]
    )
    logger.error(
        "mail sync failed account=%s error_class=%s detail=%s",
        failure["account"],
        failure["error_class"],
        detail,
    )


class MailSyncBatchError(RuntimeError):
    """All accounts were attempted, but at least one did not sync completely."""

    def __init__(self, results: list[dict], failures: list[dict[str, object]]):
        self.results = results
        self.failures = failures
        aliases = ", ".join(str(item["account"]) for item in failures)
        super().__init__(f"mail sync incomplete for {len(failures)} account(s): {aliases}")


class MailRuntime:
    def __init__(
        self,
        settings: Settings,
        *,
        accounts: tuple[AccountConfig, ...] | None = None,
    ):
        self.settings = settings
        self.accounts = (
            accounts if accounts is not None else load_account_configs(settings.account_config_file)
        )
        enabled = {account.alias for account in self.accounts}
        bridge_overlap = sorted(settings.thunderbird_bridge_account_set & enabled)
        if bridge_overlap:
            logger.warning(
                "Thunderbird bridge accounts are also natively enabled; they stay receive-only: %s",
                ", ".join(bridge_overlap),
            )
        unknown = sorted(settings.uidplus_move_account_set - enabled)
        if unknown:
            logger.warning(
                "UIDPLUS move configured for accounts that are not enabled: %s", ", ".join(unknown)
            )
        self.uidplus_move_accounts = self.policy.uidplus_move_accounts
        if any(
            account.copy_preserve_source_fallback
            for account in self.accounts
            if account.alias in self.uidplus_move_accounts
        ):
            raise RuntimeError(
                "account cannot enable both copy_preserve_source_fallback and UIDPLUS move"
            )
        self.store = CredentialStore.from_key_file(
            settings.credential_db,
            key_file=settings.credential_key_file,
            host_id=settings.host_id,
        )
        self.oauth_clients = self._build_oauth_clients(self.accounts)
        master_key = read_key_file(settings.credential_key_file)
        self.archive_writer = ArchiveWriter(
            settings.archive_dir,
            attachment_key=master_key,
            folder_precedence=folder_precedence_by_alias(self.accounts),
        )
        self.archive_reader = ArchiveReader(
            settings.archive_dir,
            attachment_key=master_key,
        )
        self.sync = ReadOnlyMailboxSync(
            archive=self.archive_writer,
            credentials=self.store,
            oauth_access_token=self.oauth_access_token,
        )
        self.staged_attachments = StagedAttachmentStore(self.store)
        self.actions = MailActionExecutor(
            accounts=self.accounts,
            archive=self.archive_reader,
            archive_writer=self.archive_writer,
            credentials=self.store,
            oauth_access_token=self.oauth_access_token,
            staged_attachments=self.staged_attachments,
            uidplus_move_accounts=self.uidplus_move_accounts,
        )

    def _build_oauth_clients(self, accounts):
        settings = self.settings
        return {
            account.alias: GoogleOAuthClient(
                store=self.store,
                record_id=account.credential_record,
                expected_address=account.address,
                redirect_uri=settings.google_oauth_redirect_uri,
            )
            if account.oauth_provider == "google"
            else MicrosoftOAuthClient(
                store=self.store,
                record_id=account.credential_record,
                registration=microsoft_registration(settings),
            )
            for account in accounts
            if account.auth_kind == "oauth2"
        }

    def oauth_authorization_clients(self):
        """Allow disabled mailboxes to authorize without enabling mail operations."""
        return self._build_oauth_clients(
            load_account_configs(self.settings.account_config_file, include_disabled=True)
        )

    @property
    def policy(self) -> AccountPolicy:
        """Rebuilt per access so bridge mailboxes added to the account
        config file become readable without a restart."""
        return AccountPolicy.build(self.settings, self.accounts)

    @property
    def receive_only_accounts(self) -> frozenset[str]:
        return self.policy.receive_only_accounts

    @property
    def read_accounts(self):
        return self.policy.read_accounts

    def oauth_access_token(self, account: AccountConfig, *, force_refresh: bool = False) -> str:
        # Microsoft IMAP can reject a nominally unexpired access token before
        # the locally recorded timestamp. Refresh the host-local credential
        # 30 minutes early; the record lock prevents concurrent refreshes.
        options = {"refresh_margin_seconds": MICROSOFT_REFRESH_MARGIN_SECONDS}
        if force_refresh:
            options["force_refresh"] = True
        return self.oauth_clients[account.alias].access_token(**options)

    def sync_all(self, *, per_folder_limit: int = 500) -> list[dict]:
        results: list[dict] = []
        failures: list[dict[str, object]] = []
        for account in self.accounts:
            try:
                results.append(self.sync.sync_account(account, per_folder_limit=per_folder_limit))
            except MailboxSyncIncomplete as exc:
                results.append(exc.result)
                failures.append(_sync_failure(account.alias, exc))
            except Exception as exc:
                failures.append(_sync_failure(account.alias, exc))
        for failure in failures:
            _log_sync_failure(failure)
        if failures:
            raise MailSyncBatchError(results, failures)
        return results

    def sync_selected(self, account: str | None, *, per_folder_limit: int = 500) -> list[dict]:
        if account is None:
            return self.sync_all(per_folder_limit=per_folder_limit)
        configured = next((item for item in self.accounts if item.alias == account), None)
        if configured is None:
            raise ValueError("unknown or disabled account")
        try:
            return [self.sync.sync_account(configured, per_folder_limit=per_folder_limit)]
        except MailboxSyncIncomplete as exc:
            failure = _sync_failure(account, exc)
            _log_sync_failure(failure)
            raise MailSyncBatchError([exc.result], [failure]) from exc
        except Exception as exc:
            failure = _sync_failure(account, exc)
            _log_sync_failure(failure)
            raise MailSyncBatchError([], [failure]) from exc

    def list_sent_metadata(
        self,
        account: str | None,
        *,
        since: dt.datetime,
        before: dt.datetime,
        per_account_limit: int,
    ) -> list[dict]:
        configured = (
            self.accounts
            if account is None
            else tuple(item for item in self.accounts if item.alias == account)
        )
        if not configured:
            raise ValueError("unknown or disabled account")
        rows = [
            row
            for item in configured
            for row in self.actions.list_sent_metadata(
                item.alias,
                since=since,
                before=before,
                limit=per_account_limit,
            )
        ]
        return sorted(rows, key=lambda item: item["date_received"], reverse=True)

    def refresh_readiness(self) -> list[dict[str, object]]:
        """Inspect encrypted provider credentials without refreshing them."""
        results: list[dict[str, object]] = []
        metadata = {item["record_id"]: item for item in self.store.metadata()}
        now = dt.datetime.now(dt.UTC)
        for alias, client in self.oauth_clients.items():
            try:
                value = self.store.get(client.record_id)
                record_metadata = metadata[client.record_id]
            except (CredentialNotFound, KeyError):
                results.append(
                    {
                        "account": alias,
                        "status": "authorization_required",
                        "has_refresh_token": False,
                        "has_access_token": False,
                        "access_token_expired": True,
                        "would_refresh_within_hour": True,
                    }
                )
                continue
            raw_expiry = value.get("expires_at") or value.get("access_token_expiration")
            try:
                expires = dt.datetime.fromisoformat(str(raw_expiry).replace("Z", "+00:00"))
                expires = expires.replace(tzinfo=expires.tzinfo or dt.UTC).astimezone(dt.UTC)
            except (TypeError, ValueError):
                expires = None
            failure = value.get("oauth_failure") or {}
            if (
                not value.get("refresh_token")
                or failure.get("reauthorization_required")
                or (isinstance(client, GoogleOAuthClient) and client.authorization_required(value))
            ):
                status = "authorization_required"
            elif not value.get("access_token") or expires is None or expires <= now:
                status = "refresh_required"
            else:
                status = "ready"
            results.append(
                {
                    "account": alias,
                    "status": status,
                    "last_refresh_error": failure.get("error"),
                    "last_refresh_error_codes": failure.get("error_codes", []),
                    "credential_version": str(record_metadata["version"]),
                    "updated_at": str(record_metadata["updated_at"]),
                    "has_refresh_token": bool(value.get("refresh_token")),
                    "has_access_token": bool(value.get("access_token")),
                    "access_token_expired": expires is None or expires <= now,
                    "would_refresh_within_hour": expires is None
                    or expires <= now + dt.timedelta(hours=1),
                }
            )
        return results
