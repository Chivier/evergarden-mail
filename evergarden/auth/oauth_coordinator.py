from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from collections.abc import Mapping

from evergarden.auth.credential_store import CredentialStore, CredentialStoreError
from evergarden.auth.google_oauth import GoogleOAuthClient
from evergarden.auth.provider_oauth import MicrosoftOAuthClient


class OAuthStateError(RuntimeError):
    pass


def _parse_timestamp(value: object) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


class OAuthCoordinator:
    """Persist PKCE state in the encrypted host store and consume it once."""

    def __init__(
        self,
        *,
        store: CredentialStore,
        clients: Mapping[str, MicrosoftOAuthClient | GoogleOAuthClient],
        now=None,
    ):
        self.store = store
        self.clients = dict(clients)
        self.now = now or (lambda: dt.datetime.now(dt.UTC))

    @staticmethod
    def _record_id(state: str) -> str:
        return "oauth-pending:" + hashlib.sha256(state.encode()).hexdigest()

    def start(self, account: str) -> dict[str, object]:
        try:
            client = self.clients[account]
        except KeyError as exc:
            raise OAuthStateError("unknown OAuth account") from exc
        if getattr(client, "uses_device_authorization", False):
            request = client.start_device_authorization()
            flow_id = secrets.token_urlsafe(32)
            self.store.put(
                self._record_id(flow_id),
                {
                    "flow": "device_code",
                    "account": account,
                    "state": flow_id,
                    "device_code": request["device_code"],
                    "expires_at": request["expires_at"],
                    "interval": request["interval"],
                    "status": "authorization_pending",
                    "next_poll_at": (
                        self.now() + dt.timedelta(seconds=request["interval"])
                    ).isoformat(),
                },
            )
            return {
                "flow": "device_code",
                "flow_id": flow_id,
                "user_code": request["user_code"],
                "verification_uri": request["verification_uri"],
                "expires_at": request["expires_at"],
                "interval": request["interval"],
            }
        request = client.build_authorization_request()
        self.store.put(
            self._record_id(request.state),
            {
                "account": account,
                "provider": getattr(client, "provider", "microsoft"),
                "authorization_binding": getattr(client, "authorization_binding", None),
                "state": request.state,
                "code_verifier": request.code_verifier,
                "expires_at": request.expires_at.isoformat(timespec="seconds"),
                "consumed": False,
            },
        )
        return {
            "authorization_url": request.url,
            "state": request.state,
            "expires_at": request.expires_at.isoformat(timespec="seconds"),
        }

    def callback(self, *, state: str, code: str, provider: str = "microsoft") -> dict[str, str]:
        if not state or not code:
            raise OAuthStateError("authorization state and code are required")
        record_id = self._record_id(state)
        try:
            pending, version = self.store.get_with_version(record_id)
        except CredentialStoreError as exc:
            raise OAuthStateError("authorization state is unknown") from exc
        if (
            pending.get("state") != state
            or pending.get("consumed")
            or pending.get("flow") == "device_code"
        ):
            raise OAuthStateError("authorization state is invalid or already consumed")
        expires = dt.datetime.fromisoformat(str(pending["expires_at"]).replace("Z", "+00:00"))
        if expires.astimezone(dt.UTC) <= self.now():
            raise OAuthStateError("authorization state is expired")
        account = str(pending["account"])
        try:
            client = self.clients[account]
        except KeyError as exc:
            raise OAuthStateError("authorization account is no longer configured") from exc
        if (
            provider != pending.get("provider", "microsoft")
            or provider != getattr(client, "provider", "microsoft")
            or pending.get("authorization_binding")
            != getattr(client, "authorization_binding", None)
        ):
            raise OAuthStateError("authorization provider or account configuration has changed")
        verifier = str(pending["code_verifier"])
        claimed = {**pending, "consumed": True, "status": "exchanging", "code_verifier": "consumed"}
        claim_version = self.store.put_if_version(
            record_id,
            expected_version=version,
            value=claimed,
            event="oauth-state-claimed",
        )
        client.exchange_code(code=code, code_verifier=verifier)
        self.store.put_if_version(
            record_id,
            expected_version=claim_version,
            value={**claimed, "code_verifier": "consumed", "status": "authorized"},
            event="oauth-state-consumed",
        )
        return {"account": account, "status": "authorized"}

    def prune_pending(self, *, retain: dt.timedelta = dt.timedelta(days=1)) -> int:
        """Delete pending-state records whose flow can no longer complete.

        Every ``oauth-pending:*`` record carries the flow's ``expires_at``;
        once that lies ``retain`` in the past the record is dead weight
        (consumed, authorized-and-synced, declined, or simply abandoned) and
        only grows the store and the maintenance scan. Unreadable records old
        enough are deleted too — they can never be used again.
        """
        cutoff = self.now() - retain
        pruned = 0
        for metadata in self.store.metadata():
            record_id = str(metadata["record_id"])
            if not record_id.startswith("oauth-pending:"):
                continue
            try:
                value = self.store.get(record_id)
            except CredentialStoreError:
                updated = _parse_timestamp(metadata.get("updated_at"))
                if updated is not None and updated <= cutoff:
                    pruned += int(self.store.delete(record_id, event="pruned-unreadable"))
                continue
            expires = _parse_timestamp(value.get("expires_at"))
            if expires is None:
                # A missing or unparseable expiry must not kill an in-flight
                # flow created moments ago; age it by the record file instead.
                updated = _parse_timestamp(metadata.get("updated_at"))
                if updated is not None and updated <= cutoff:
                    pruned += int(self.store.delete(record_id, event="pruned"))
                continue
            if expires <= cutoff:
                pruned += int(self.store.delete(record_id, event="pruned"))
        return pruned

    def poll_device(self, flow_id: str) -> dict[str, object]:
        record_id = self._record_id(flow_id)
        try:
            pending, version = self.store.get_with_version(record_id)
        except CredentialStoreError as exc:
            raise OAuthStateError("authorization state is unknown") from exc
        if pending.get("flow") != "device_code" or pending.get("state") != flow_id:
            raise OAuthStateError("authorization state is invalid")
        account = str(pending["account"])
        if pending["status"] == "authorized":
            return {"account": account, "status": "authorized"}
        if pending["status"] in {"authorization_declined", "expired_token"}:
            raise OAuthStateError("authorization was declined or expired; start again")
        now = self.now()
        if now >= dt.datetime.fromisoformat(pending["expires_at"]):
            raise OAuthStateError("authorization state is expired; start again")
        interval = int(pending["interval"])
        if now < dt.datetime.fromisoformat(pending["next_poll_at"]):
            return {"account": account, "status": "authorization_pending", "interval": interval}
        client = self.clients.get(account)
        if client is None or not getattr(client, "uses_device_authorization", False):
            raise OAuthStateError("authorization account is no longer configured")
        claimed = {**pending, "next_poll_at": (now + dt.timedelta(seconds=35)).isoformat()}
        try:
            claim_version = self.store.put_if_version(
                record_id, expected_version=version, value=claimed
            )
        except CredentialStoreError:
            return {"account": account, "status": "authorization_pending", "interval": interval}
        status = client.poll_device_authorization(str(pending["device_code"]))
        if status == "slow_down":
            interval += 5
        updated = {
            **claimed,
            "status": status,
            "interval": interval,
            "next_poll_at": (self.now() + dt.timedelta(seconds=interval)).isoformat(),
        }
        if status in {"authorized", "authorization_declined", "expired_token"}:
            updated.pop("device_code", None)
        self.store.put_if_version(record_id, expected_version=claim_version, value=updated)
        return {"account": account, "status": status, "interval": interval}
