"""Durable, deduplicated feedback. User decisions never grant execution approval."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

from evergarden.archive.sqlite_archive import _private_sqlite_path, open_readonly
from evergarden.mail.diagnostics import SERVICE_VERSION, LocationSnapshot, feedback_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS issues (
    issue_id TEXT PRIMARY KEY,
    stable_message_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    intended_action TEXT NOT NULL,
    user_decision TEXT NOT NULL,
    reported_processing_status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    diagnostic_id TEXT NOT NULL,
    UNIQUE(stable_message_id,reason_code)
);
CREATE TABLE IF NOT EXISTS issue_events (
    event_id INTEGER PRIMARY KEY,
    issue_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    event_json TEXT NOT NULL
);
"""


class FeedbackStore:
    def __init__(self, data_dir: Path):
        self.path = data_dir / "location-feedback.db"

    def submit(
        self,
        snapshot: LocationSnapshot,
        *,
        stable_message_id: str,
        intended_action: str,
        user_decision: str,
        processing_status: str,
        reason_code: str,
    ) -> dict:
        state = snapshot.state(stable_message_id)
        if not state["reason_code"] or reason_code != state["reason_code"]:
            raise ValueError("reason_code must match the current diagnostic")
        if intended_action not in {"archive", "trash", "mark", "move"}:
            raise ValueError("invalid intended_action")
        if user_decision not in {"authorized", "pending", "rejected"}:
            raise ValueError("invalid user_decision")
        if processing_status not in {"pending_approval", "blocked", "unknown"}:
            raise ValueError("feedback cannot claim confirmed execution")
        now = dt.datetime.now(dt.UTC).isoformat()
        _private_sqlite_path(self.path, writable=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as conn:
            # Harden before schema or user decisions are written.
            self.path.chmod(0o600)
            conn.row_factory = sqlite3.Row
            conn.executescript(SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT issue_id FROM issues WHERE stable_message_id=? AND reason_code=?",
                (stable_message_id, reason_code),
            ).fetchone()
            issue_id = str(existing[0]) if existing else str(uuid.uuid4())
            conn.execute(
                "INSERT INTO issues VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(stable_message_id,reason_code) DO UPDATE SET "
                "intended_action=excluded.intended_action,user_decision=excluded.user_decision,"
                "reported_processing_status=excluded.reported_processing_status,updated_at=excluded.updated_at",
                (
                    issue_id,
                    stable_message_id,
                    reason_code,
                    intended_action,
                    user_decision,
                    processing_status,
                    now,
                    now,
                    state["diagnostic_id"],
                ),
            )
            # Strict allowlist: no arbitrary logs, mail content or credential fields.
            event = {
                "intended_action": intended_action,
                "user_decision": user_decision,
                "processing_status": processing_status,
                "diagnostic_id": state["diagnostic_id"],
                "request_id": snapshot.request_id,
                "sync_run_id": state["sync_run_id"],
                "service_version": SERVICE_VERSION,
            }
            conn.execute(
                "INSERT INTO issue_events(issue_id,recorded_at,event_json) VALUES (?,?,?)",
                (issue_id, now, json.dumps(event)),
            )
            conn.commit()
        return {**self.get(snapshot, issue_id), "deduplicated": bool(existing)}

    def _rows(self) -> list[dict]:
        if not self.path.is_file():
            return []
        with closing(open_readonly(self.path)) as conn:
            return [
                dict(row)
                for row in conn.execute("SELECT * FROM issues ORDER BY created_at,issue_id")
            ]

    @staticmethod
    def _present(snapshot: LocationSnapshot, row: dict) -> dict:
        mid = row["stable_message_id"]
        state = snapshot.state(mid) if mid in snapshot.messages else None
        operations = snapshot.executions.get(mid, [])
        relevant = [
            x
            for x in operations
            if x["kind"] == row["intended_action"] and x["updated_at"] >= row["created_at"]
        ]
        outcome = (
            max(relevant, key=lambda x: x["updated_at"])["state"] if relevant else "NOT_EXECUTED"
        )
        blocked_unknown = any(x["state"] in {"UNKNOWN", "ATTEMPTING"} for x in operations)
        restored = bool(state and state["actionable"]) and not blocked_unknown
        processing_status = (
            "unknown"
            if blocked_unknown
            else "confirmed"
            if outcome == "CONFIRMED"
            else "message_removed"
            if state is None
            else "pending_approval"
            if restored
            else row["reported_processing_status"]
        )
        return {
            **row,
            "feedback_url": snapshot.base_url + feedback_path(mid, row["issue_id"]),
            "current_location": state,
            "restored_actionable": restored,
            "repair_result": "observed_actionable" if restored else "awaiting_verification",
            "processing_status": processing_status,
            "execution_result": outcome,
            "blocking_operations": [
                x for x in operations if x["state"] in {"UNKNOWN", "ATTEMPTING"}
            ],
            "requires_new_approval": True,
            "feedback_grants_approval": False,
        }

    def get(self, snapshot: LocationSnapshot, issue_id: str) -> dict:
        row = next((row for row in self._rows() if row["issue_id"] == issue_id), None)
        if row is None:
            raise ValueError("feedback issue not found")
        with closing(open_readonly(self.path)) as conn:
            events = [
                {"recorded_at": x["recorded_at"], **json.loads(x["event_json"])}
                for x in conn.execute(
                    "SELECT recorded_at,event_json FROM issue_events WHERE issue_id=? ORDER BY event_id",
                    (issue_id,),
                )
            ]
        return {**self._present(snapshot, row), "history": events}

    def list(
        self,
        snapshot: LocationSnapshot,
        *,
        restored_only: bool = False,
        after: str | None = None,
        limit: int = 20,
    ) -> dict:
        rows = [self._present(snapshot, row) for row in self._rows()]
        if restored_only:
            rows = [row for row in rows if row["restored_actionable"]]
        if after:
            # UUID is the identity anchor; sort by insertion timestamp plus UUID.
            anchor = next((row for row in self._rows() if row["issue_id"] == after), None)
            if anchor is None:
                raise ValueError("feedback cursor not found")
            rows = [
                row
                for row in rows
                if (row["created_at"], row["issue_id"]) > (anchor["created_at"], after)
            ]
        bounded = max(1, min(limit, 100))
        return {
            "items": rows[:bounded],
            "next_cursor": rows[bounded - 1]["issue_id"] if len(rows) > bounded else None,
        }
