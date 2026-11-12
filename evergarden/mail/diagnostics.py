"""Content-free location evidence, shared by MCP lists, counters and diagnostics."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import threading
import time
import uuid
from contextlib import closing
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from evergarden.archive.sqlite_archive import (
    PUBLIC_MESSAGE_COLUMNS_SQL,
    ArchiveReader,
    _utc_boundary,
    open_readonly,
)

# Stamped at image build time (Dockerfile ARG) so logs and audit rows name the
# code that actually ran; the literal is only a fallback for source checkouts.
SERVICE_VERSION = os.environ.get("EVERGARDEN_SERVICE_VERSION") or "source-checkout"
REQUEST_ID: ContextVar[str | None] = ContextVar("mail_diagnostic_request_id", default=None)
LOCATION_STATUSES = (
    "valid",
    "moved_confirmed",
    "missing",
    "uidvalidity_changed",
    "auth_failed",
    "unverified",
    "ambiguous",
)
REASONS = {
    "valid": None,
    "moved_confirmed": "PROVIDER_MOVE_CONFIRMED",
    "missing": "NO_ACTIVE_PROVIDER_LOCATION",
    "uidvalidity_changed": "UIDVALIDITY_CHANGED",
    "auth_failed": "AUTHENTICATION_FAILED",
    "unverified": "PROVIDER_LOCATION_NOT_VERIFIED",
    "ambiguous": "AMBIGUOUS_PROVIDER_LOCATIONS",
}


class LocationActionBlocked(ValueError):
    def __init__(self, detail: dict):
        self.detail = detail
        super().__init__(
            "message has no current provider location for this action"
            if detail["reason_code"] == "NO_ACTIVE_PROVIDER_LOCATION"
            else f"mail action blocked: {detail['reason_code']}"
        )


def diagnostic_id(stable_id: str, reason: str | None) -> str:
    return hashlib.sha256(f"{stable_id}:{reason or 'OK'}".encode()).hexdigest()[:24]


def feedback_path(stable_id: str, issue_id: str | None = None) -> str:
    return "/feedback?" + urlencode(
        {"message_id": stable_id, **({"issue_id": issue_id} if issue_id else {})}
    )


class LocationEvidence:
    """Archive-derived location evidence; immutable once built and shared across requests."""

    def __init__(self, archive: ArchiveReader):
        self.messages: dict[str, dict] = {}
        self.locations: dict[str, list[dict]] = {}
        self.observations: dict[str, list[dict]] = {}
        self.sync: dict[tuple[str, str], dict] = {}
        self.attempts: dict[tuple[str, str], dict] = {}
        self.events: dict[tuple[str, str, str], dict] = {}
        self.identity_verifications: dict[tuple, dict] = {}
        self.location_history_ids: set[str] = set()
        live_accounts: set[str] = set()
        hot_identities: set[str] = set()
        for path in archive.paths():
            with closing(open_readonly(path)) as conn:
                # All evidence in a shard must describe one committed state.
                # Separate autocommit SELECTs can mix a pre-sync UIDVALIDITY
                # with post-sync locators and invent a transient anomaly.
                conn.execute("BEGIN")
                tables = {
                    str(row[0])
                    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                is_hot = path.name == "mail-hot.db"
                if is_hot:
                    if "provider_identity_verifications" in tables:
                        self.identity_verifications = {
                            (
                                row["stable_id"],
                                row["account"],
                                row["folder"].casefold(),
                                row["uid_validity"],
                                row["uid"],
                            ): dict(row)
                            for row in conn.execute("SELECT * FROM provider_identity_verifications")
                        }
                    if "shadow_sync_state" in tables:
                        self.sync = {
                            (str(row["account"]), str(row["folder"]).casefold()): dict(row)
                            for row in conn.execute("SELECT * FROM shadow_sync_state")
                        }
                        live_accounts = {
                            row["account"] for row in self.sync.values() if row["uid_validity"]
                        }
                    if "sync_attempts" in tables:
                        self.attempts = {
                            (str(row["account"]), str(row["folder"]).casefold()): dict(row)
                            for row in conn.execute("SELECT * FROM sync_attempts")
                        }
                # Deduplicate BEFORE applying filters: a stale shard must not
                # reintroduce a message whose hot copy has moved or become read.
                for row in conn.execute(
                    f"SELECT {PUBLIC_MESSAGE_COLUMNS_SQL},uid,raw_body_sha256,updated_at FROM messages"  # noqa: S608
                ):
                    self.messages.setdefault(str(row["id"]), dict(row))
                for table, destination in (
                    ("message_locations", self.locations),
                    ("provider_uid_observations", self.observations),
                ):
                    if table not in tables:
                        continue
                    for row in conn.execute(f"SELECT * FROM {table}"):  # noqa: S608 - fixed table names
                        item = dict(row)
                        mid = str(item["stable_id"])
                        self.location_history_ids.add(mid)
                        if not is_hot and (
                            item["account"] in live_accounts or mid in hot_identities
                        ):
                            continue
                        key = (item["account"], item["folder"], item["uid_validity"], item["uid"])
                        existing = destination.setdefault(mid, [])
                        if not any(
                            (x["account"], x["folder"], x["uid_validity"], x["uid"]) == key
                            for x in existing
                        ):
                            existing.append(item)
                        if is_hot:
                            hot_identities.add(mid)
                if "location_events" in tables:
                    for row in conn.execute("SELECT * FROM location_events ORDER BY event_id"):
                        item = dict(row)
                        key = (item["stable_id"], item["account"], item["folder"].casefold())
                        if is_hot or key not in self.events:
                            self.events[key] = item


def _read_header(path: Path, start: int, end: int) -> tuple[os.stat_result, bytes] | None:
    try:
        with path.open("rb") as handle:
            return os.fstat(handle.fileno()), handle.read(end)[start:]
    except FileNotFoundError:
        return None


def _shard_fingerprint(paths: list[Path]) -> tuple:
    """Identify the committed state of every shard without opening SQLite.

    The database header carries the rollback-mode change counter and the WAL
    header its checkpoint generation and salts. Every WAL commit advances
    mxFrame and the frame checksum in the wal-index header (-shm bytes 16-40).
    The rest of -shm, and its stat data, change whenever a first connection
    re-runs wal-index recovery, so they are deliberately excluded. A missing
    and an empty WAL hold no frames: the last writer deletes it on close and
    the next reader recreates it, which must not count as a commit.
    """
    parts: list[tuple] = []
    for path in paths:
        database = _read_header(path, 0, 100)
        if database is None:
            parts.append((str(path), None))
            continue
        stat, header = database
        parts.append((str(path), stat.st_ino, stat.st_size, stat.st_mtime_ns, header))
        wal = _read_header(path.with_name(path.name + "-wal"), 0, 32)
        if wal is None or wal[0].st_size == 0:
            continue
        stat, header = wal
        shm = _read_header(path.with_name(path.name + "-shm"), 16, 40)
        parts.append((stat.st_ino, stat.st_size, stat.st_mtime_ns, header, shm[1] if shm else None))
    return tuple(parts)


class LocationEvidenceCache:
    """Share one evidence build between requests until any shard commits.

    Building evidence scans every shard (seconds when the page cache is cold);
    rebuilding it per request let a handful of concurrent UI reads exhaust the
    mail UI's MCP timeout. The fingerprint is taken before the build, so a
    commit racing the build only causes one extra rebuild, never a stale hit.
    """

    def __init__(self, archive: ArchiveReader, *, max_age_seconds: float = 60.0):
        self.archive = archive
        self.max_age_seconds = max_age_seconds
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._built_at = 0.0
        self._evidence: LocationEvidence | None = None

    def get(self) -> LocationEvidence:
        with self._lock:
            key = _shard_fingerprint(self.archive.paths())
            fresh = time.monotonic() - self._built_at < self.max_age_seconds
            if self._evidence is None or key != self._key or not fresh:
                self._evidence = LocationEvidence(self.archive)
                self._key = key
                self._built_at = time.monotonic()
            return self._evidence


class LocationSnapshot:
    """Read-only indexed evidence; never contacts a provider or repairs a locator.

    Hot locations are authoritative for synchronized accounts. Tombstones and
    absent hot identities must never be resurrected from copy-only year shards.
    """

    def __init__(
        self,
        archive: ArchiveReader,
        *,
        now: dt.datetime | None = None,
        executions=None,
        base_url: str = "",
        evidence: LocationEvidence | None = None,
    ):
        self.archive = archive
        self.request_id = REQUEST_ID.get() or str(uuid.uuid4())
        self.base_url = base_url.rstrip("/")
        self.now = now or dt.datetime.now(dt.UTC)
        self.executions = executions or {}
        if evidence is None:
            evidence = LocationEvidence(archive)
        self.messages = evidence.messages
        self.locations = evidence.locations
        self.observations = evidence.observations
        self.sync = evidence.sync
        self.attempts = evidence.attempts
        self.events = evidence.events
        self.identity_verifications = evidence.identity_verifications
        self.location_history_ids = evidence.location_history_ids

    def _verified(self, location: dict) -> bool:
        sync = self.sync.get((location["account"], location["folder"].casefold()))
        return bool(
            location["active"]
            and location["uid"] > 0
            and location["uid_validity"]
            and sync
            and sync["uid_validity"] == location["uid_validity"]
        )

    def _identity_match_basis(self, location: dict, message: dict) -> str | None:
        provider_hash = location["raw_body_sha256"]
        archive_hash = message["raw_body_sha256"]
        if not provider_hash or not archive_hash:
            return None
        if provider_hash == archive_hash:
            return "exact_raw_hash"
        proof = self.identity_verifications.get(
            (
                message["id"],
                location["account"],
                location["folder"].casefold(),
                location["uid_validity"],
                location["uid"],
            ),
            {},
        )
        if (
            proof.get("provider_raw_body_sha256") == provider_hash
            and proof.get("archive_raw_body_sha256") == archive_hash
        ):
            return "verified_provider_equivalence"
        return None

    def state(self, mid: str) -> dict[str, Any]:
        self.archive._validate_stable_id(mid)
        if mid not in self.messages:
            raise ValueError("message not found")
        message = self.messages[mid]
        account, folder = message["account"], str(message["folder"] or "")
        key = (account, folder.casefold())
        sync = self.sync.get(key, {})
        attempt = self.attempts.get(key, {})
        locations = self.locations.get(mid, [])
        current = [
            x
            for x in locations
            if x["account"] == account and x["folder"].casefold() == folder.casefold()
        ]
        active = [x for x in current if x["active"] and x["uid"] > 0]
        status, reason = "unverified", REASONS["unverified"]
        last_verified = None
        if current or (sync.get("uid_validity") and mid in self.location_history_ids):
            status, reason = "missing", REASONS["missing"]
        if any(
            x["uid_validity"]
            and sync.get("uid_validity")
            and x["uid_validity"] != sync["uid_validity"]
            for x in current
        ):
            status, reason = "uidvalidity_changed", REASONS["uidvalidity_changed"]
        verified = [x for x in active if self._verified(x)]
        provider_present = bool(verified) and all(
            self._identity_match_basis(x, message) is not None for x in verified
        )
        if verified:
            last_verified = sync.get("last_synced_at")
            status, reason = "valid", None
            if any(self._identity_match_basis(x, message) is None for x in verified):
                status, reason = "unverified", "PROVIDER_IDENTITY_MISMATCH"
            duplicate_uids = {
                x["uid"]
                for x in self.observations.get(mid, [])
                if x["account"] == account
                and x["folder"].casefold() == folder.casefold()
                and self._verified(x)
            }
            if len(duplicate_uids) > 1:
                status, reason = "ambiguous", REASONS["ambiguous"]
            if last_verified and self.now - dt.datetime.fromisoformat(last_verified) > dt.timedelta(
                hours=24
            ):
                status, reason = "unverified", "PROVIDER_VERIFICATION_STALE"
        elif active and status != "uidvalidity_changed":
            status, reason = "unverified", REASONS["unverified"]
        event = self.events.get((mid, account, folder.casefold()))
        if not active and event and event["reason_code"] == "PROVIDER_MOVE_CONFIRMED":
            status, reason = "moved_confirmed", REASONS["moved_confirmed"]
        # A newer failed attempt invalidates confidence in older successful syncs.
        if attempt.get("status") == "failed" and attempt["attempted_at"] >= sync.get(
            "last_synced_at", ""
        ):
            status = (
                "auth_failed" if attempt["reason_code"] == "AUTHENTICATION_FAILED" else "unverified"
            )
            reason = attempt["reason_code"]
        location_reason = reason
        unknown = any(x["state"] in {"UNKNOWN", "ATTEMPTING"} for x in self.executions.get(mid, []))
        if unknown:
            reason = "PROVIDER_OUTCOME_UNKNOWN"
        return {
            "stable_message_id": mid,
            "indexed_folder": folder,
            "location_status": status,
            "actionable": status == "valid" and not unknown,
            "provider_present": provider_present,
            "historical_copy_only": not provider_present,
            "reason_code": reason,
            "location_reason_code": location_reason,
            "reason_codes": list(dict.fromkeys(x for x in (location_reason, reason) if x)),
            "last_provider_verified_at": last_verified,
            "last_sync_at": sync.get("last_synced_at"),
            "sync_run_id": attempt.get("sync_run_id"),
            "diagnostic_id": diagnostic_id(mid, reason),
            "feedback_url": self.base_url + feedback_path(mid),
        }

    def diagnose(self, mid: str) -> dict:
        state = self.state(mid)
        message = self.messages[mid]
        evidence = []
        for location in self.locations.get(mid, []):
            key = (location["account"], location["folder"].casefold())
            sync = self.sync.get(key, {})
            event = self.events.get((mid, *key))
            evidence.append(
                {
                    "account": location["account"],
                    "folder": location["folder"],
                    "uid": location["uid"],
                    "uid_validity": location["uid_validity"],
                    "active": bool(location["active"]),
                    "observed_at": location["observed_at"],
                    "current_uid_validity": sync.get("uid_validity"),
                    "uid_validity_matches": bool(
                        location["uid_validity"]
                        and location["uid_validity"] == sync.get("uid_validity")
                    ),
                    "indexed_uid_matches": location["uid"] == message["uid"]
                    if location["folder"].casefold() == state["indexed_folder"].casefold()
                    else None,
                    "identity_hash_matches": bool(
                        location["raw_body_sha256"]
                        and location["raw_body_sha256"] == message["raw_body_sha256"]
                    ),
                    "identity_verified": self._identity_match_basis(location, message) is not None,
                    "identity_match_basis": self._identity_match_basis(location, message),
                    "deactivated_at": (event["recorded_at"] if event else None)
                    if not location["active"]
                    else None,
                    "deactivation_reason": (
                        event["reason_code"] if event else "HISTORICAL_REASON_NOT_RECORDED"
                    )
                    if not location["active"]
                    else None,
                    "sync_run_id": self.attempts.get(key, {}).get("sync_run_id"),
                }
            )
        matches = [
            {
                "account": x["account"],
                "folder": x["folder"],
                "uid": x["uid"],
                "match_basis": [
                    "stable_message_id",
                    "raw_body_sha256"
                    if x["identity_match_basis"] == "exact_raw_hash"
                    else x["identity_match_basis"],
                ]
                if x["identity_verified"]
                else ["stable_message_id"],
                "confidence": "high"
                if x["identity_verified"] and x["uid_validity_matches"]
                else "unverified",
            }
            for x in evidence
            if x["active"] and x["folder"].casefold() != state["indexed_folder"].casefold()
        ]
        attempt = self.attempts.get((message["account"], state["indexed_folder"].casefold()))
        return {
            **state,
            "account": message["account"],
            "indexed_uid": message["uid"],
            "provider_location_exists": any(
                x["active"] and x["uid_validity_matches"] and x["identity_verified"]
                for x in evidence
            ),
            "provider_location_history_exists": mid in self.location_history_ids,
            "provider_locations": evidence,
            "provider_uid_observations": [
                {
                    "account": x["account"],
                    "folder": x["folder"],
                    "uid": x["uid"],
                    "uid_validity": x["uid_validity"],
                    "active": bool(x["active"]),
                    "observed_at": x["observed_at"],
                }
                for x in self.observations.get(mid, [])
            ],
            "latest_sync_attempt": attempt,
            "last_successful_sync": self.sync.get(
                (message["account"], state["indexed_folder"].casefold())
            ),
            "latest_sync_success": attempt["status"] == "ok" if attempt else None,
            "related_operations": self.executions.get(mid, []),
            "other_folder_matches": matches,
            "match_status": "ambiguous"
            if len(matches) > 1
            else "single"
            if matches
            else "not_found_in_index",
            "evidence_source": "local_provider_snapshots",
            "provider_queried": False,
            "requires_new_approval": True,
            "unknown_action_policy": "Verify source and destination read-only; do not replay UNKNOWN actions.",
            "service_version": SERVICE_VERSION,
            "request_id": self.request_id,
        }

    def _matching(self, **filters) -> list[tuple[dict, dict]]:
        """Filter and order (row, state) pairs; public redaction is left to the caller."""
        account, folder = filters.get("account"), filters.get("folder")
        since = _utc_boundary(filters["since"]) if filters.get("since") else None
        before = _utc_boundary(filters["before"]) if filters.get("before") else None
        status = filters.get("location_status")
        if status and status not in LOCATION_STATUSES:
            raise ValueError("invalid location_status")
        rows = []
        for mid, row in self.messages.items():
            if (account and row["account"] != account) or (folder and row["folder"] != folder):
                continue
            if filters.get("inbox_only") and str(row["folder"] or "").casefold() != "inbox":
                continue
            date = str(row["date_received"] or "")
            if (since and date < since) or (before and date >= before):
                continue
            if filters.get("unread_only") and "\\Seen" in self.archive._flags(row["flags"]):
                continue
            state = self.state(mid)
            if (filters.get("actionable_only") and not state["actionable"]) or (
                status and state["location_status"] != status
            ):
                continue
            rows.append((row, state))
        return sorted(
            rows, key=lambda x: (str(x[0]["date_received"] or ""), x[0]["id"]), reverse=True
        )

    def _present(self, row: dict, state: dict) -> dict:
        return {**self.archive._public(row), **state}

    def filtered(self, **filters) -> list[dict]:
        return [self._present(row, state) for row, state in self._matching(**filters)]

    def counts(self, **filters) -> dict:
        rows = [state for _row, state in self._matching(**filters)]
        actionable = sum(x["actionable"] for x in rows)
        unverified = sum(
            x["location_status"] == "unverified" and x["reason_code"] != "PROVIDER_OUTCOME_UNKNOWN"
            for x in rows
        )
        moved = sum(
            x["location_status"] == "moved_confirmed"
            and x["reason_code"] != "PROVIDER_OUTCOME_UNKNOWN"
            for x in rows
        )
        return {
            "count": len(rows),
            "indexed_count": len(rows),
            "actionable_count": actionable,
            "provider_present_count": sum(x["provider_present"] for x in rows),
            "historical_copy_only_count": sum(x["historical_copy_only"] for x in rows),
            "unknown_outcome_count": sum(
                x["reason_code"] == "PROVIDER_OUTCOME_UNKNOWN" for x in rows
            ),
            "location_anomaly_count": len(rows) - actionable - unverified - moved,
            "unverified_count": unverified,
            "moved_confirmed_count": moved,
            "counts_by_location_status": {
                status: sum(x["location_status"] == status for x in rows)
                for status in LOCATION_STATUSES
            },
        }

    def page(self, *, limit: int = 20, cursor: str | None = None, **filters) -> dict:
        fingerprint = hashlib.sha256(json.dumps(filters, sort_keys=True).encode()).hexdigest()
        rows = self._matching(**filters)
        if cursor:
            try:
                if len(cursor) > 2048:
                    raise ValueError
                value = json.loads(base64.urlsafe_b64decode(cursor.encode()))
                if value["version"] != 1 or value["filter"] != fingerprint:
                    raise ValueError
                after = value["after"]
                if (
                    not isinstance(after, list)
                    or len(after) != 2
                    or not all(isinstance(x, str) for x in after)
                ):
                    raise ValueError
                rows = [
                    x for x in rows if (str(x[0]["date_received"] or ""), x[0]["id"]) < tuple(after)
                ]
            except (ValueError, KeyError, TypeError, UnicodeError) as exc:
                raise ValueError("invalid cursor or cursor filters changed") from exc
        bounded = self.archive._limit(limit)
        items = [self._present(row, state) for row, state in rows[:bounded]]
        next_cursor = None
        if len(rows) > bounded:
            last = items[-1]
            value = {
                "version": 1,
                "filter": fingerprint,
                "after": [str(last["date_received"] or ""), last["id"]],
            }
            next_cursor = base64.urlsafe_b64encode(json.dumps(value).encode()).decode()
        return {
            "items": items,
            "next_cursor": next_cursor,
            "pagination": "date_received_desc_id_desc; live evidence",
        }
