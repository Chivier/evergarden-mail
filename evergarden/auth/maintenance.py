from __future__ import annotations

import datetime as dt
import logging
import time

from evergarden.audit.redaction import redact_error_detail
from evergarden.auth.google_oauth import GoogleOAuthClient
from evergarden.auth.oauth_coordinator import OAuthCoordinator
from evergarden.auth.provider_oauth import _parse_expiry
from evergarden.mail.runtime import MICROSOFT_REFRESH_MARGIN_SECONDS, MailRuntime

logger = logging.getLogger(__name__)
REFRESH_INTERVAL_SECONDS = 300


class OAuthMaintenance:
    def __init__(self, runtime: MailRuntime, *, now=None, monotonic=None):
        self.runtime = runtime
        self.store = runtime.store
        self.now = now or (lambda: dt.datetime.now(dt.UTC))
        self.monotonic = monotonic or time.monotonic
        self.coordinator = OAuthCoordinator(
            store=self.store, clients=runtime.oauth_clients, now=self.now
        )
        self.refresh_due = 0.0

    def _flows(self) -> list[dict]:
        latest: dict[str, dict] = {}
        for metadata in self.store.metadata():
            if not metadata["record_id"].startswith("oauth-pending:"):
                continue
            try:
                value = self.store.get(metadata["record_id"])
            except Exception as exc:
                # One unreadable pending record must not hide every other flow.
                logger.warning("OAuth pending record unreadable error_class=%s", type(exc).__name__)
                continue
            if value.get("flow") != "device_code":
                continue
            account = value.get("account")
            expires = _parse_expiry(value.get("expires_at"))
            if account not in self.runtime.oauth_clients or expires is None:
                continue
            if value.get("status") != "authorized" and expires <= self.now():
                continue
            if value.get("status") in {"authorization_declined", "expired_token"}:
                continue
            previous = latest.get(account)
            if previous is None or expires > _parse_expiry(previous["expires_at"]):
                latest[account] = value
        return list(latest.values())

    def _sync_authorized(self, flow_id: str) -> bool:
        record_id = self.coordinator._record_id(flow_id)
        value, version = self.store.get_with_version(record_id)
        if value.get("status") != "authorized" or value.get("sync_status") == "synced":
            return False
        next_attempt = _parse_expiry(value.get("next_sync_at"))
        if next_attempt and self.now() < next_attempt:
            return False
        claimed = {
            **value,
            "next_sync_at": (self.now() + dt.timedelta(seconds=300)).isoformat(),
        }
        claim_version = self.store.put_if_version(
            record_id, expected_version=version, value=claimed
        )
        try:
            self.runtime.sync_selected(value["account"], per_folder_limit=500)
        except Exception as exc:
            try:
                self.store.put_if_version(
                    record_id,
                    expected_version=claim_version,
                    value={
                        **claimed,
                        "sync_status": "failed",
                        "sync_error": redact_error_detail(exc),
                    },
                )
            except Exception as record_exc:
                # Keep the sync failure as the reported cause; the claim's
                # next_sync_at still spaces out the retry.
                logger.warning(
                    "OAuth sync failure not recorded error_class=%s", type(record_exc).__name__
                )
            raise
        completed = {**claimed, "sync_status": "synced", "synced_at": self.now().isoformat()}
        completed.pop("sync_error", None)
        self.store.put_if_version(record_id, expected_version=claim_version, value=completed)
        logger.info("OAuth authorization completed and mail synced account=%s", value["account"])
        return True

    def step(self) -> dict:
        report = {
            "synced_accounts": [],
            "checked_accounts": [],
            "authorization_required": [],
            "failures": [],
        }
        try:
            flows = self._flows()
        except Exception as exc:
            logger.warning("OAuth pending flows unreadable error_class=%s", type(exc).__name__)
            report["failures"].append({"account": None, "error_class": type(exc).__name__})
            flows = []
        for flow in flows:
            account = flow["account"]
            try:
                if flow["status"] != "authorized":
                    status = self.coordinator.poll_device(flow["state"])["status"]
                else:
                    status = "authorized"
                if status == "authorized" and self._sync_authorized(flow["state"]):
                    report["synced_accounts"].append(account)
            except Exception as exc:
                logger.warning(
                    "OAuth completion failed account=%s detail=%s",
                    account,
                    redact_error_detail(exc),
                )
                report["failures"].append({"account": account, "error_class": type(exc).__name__})
        if self.monotonic() >= self.refresh_due:
            self.refresh_due = self.monotonic() + REFRESH_INTERVAL_SECONDS
            try:
                pruned = self.coordinator.prune_pending()
                if pruned:
                    report["pruned_pending"] = pruned
                    logger.info("OAuth pending records pruned count=%s", pruned)
            except Exception as exc:
                # Pruning is housekeeping; it must never block token refresh.
                logger.warning("OAuth pending prune failed error_class=%s", type(exc).__name__)
            for account, client in self.runtime.oauth_clients.items():
                try:
                    value = self.store.get(client.record_id)
                    if (
                        not value.get("refresh_token")
                        or (value.get("oauth_failure") or {}).get("reauthorization_required")
                        or (
                            isinstance(client, GoogleOAuthClient)
                            and client.authorization_required(value)
                        )
                    ):
                        report["authorization_required"].append(account)
                        continue
                    client.access_token(refresh_margin_seconds=MICROSOFT_REFRESH_MARGIN_SECONDS)
                    report["checked_accounts"].append(account)
                except Exception as exc:
                    logger.warning(
                        "OAuth maintenance failed account=%s detail=%s",
                        account,
                        redact_error_detail(exc),
                    )
                    report["failures"].append(
                        {"account": account, "error_class": type(exc).__name__}
                    )
        return report
