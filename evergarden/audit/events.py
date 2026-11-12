from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import threading
import uuid
from typing import Any

from evergarden.audit.redaction import redact


@dataclasses.dataclass(frozen=True)
class AuditEvent:
    event_id: str
    event_type: str
    actor: str
    outcome: str
    metadata: dict[str, Any]
    created_at: str
    previous_hash: str
    event_hash: str


class AuditChain:
    """Append-only tamper-evident reference log; Postgres stores the same fields."""

    def __init__(self):
        self.events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def append(
        self, *, event_type: str, actor: str, outcome: str, metadata: dict[str, Any]
    ) -> AuditEvent:
        with self._lock:
            previous = self.events[-1].event_hash if self.events else "0" * 64
            created = dt.datetime.now(dt.UTC).isoformat(timespec="microseconds")
            safe_metadata = redact(metadata)
            material = json.dumps(
                {
                    "event_type": event_type,
                    "actor": actor,
                    "outcome": outcome,
                    "metadata": safe_metadata,
                    "created_at": created,
                    "previous_hash": previous,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            event = AuditEvent(
                event_id=uuid.uuid4().hex,
                event_type=event_type,
                actor=actor,
                outcome=outcome,
                metadata=safe_metadata,
                created_at=created,
                previous_hash=previous,
                event_hash=hashlib.sha256(material.encode()).hexdigest(),
            )
            self.events.append(event)
            return event

    def verify(self) -> bool:
        previous = "0" * 64
        for event in self.events:
            material = json.dumps(
                {
                    "event_type": event.event_type,
                    "actor": event.actor,
                    "outcome": event.outcome,
                    "metadata": event.metadata,
                    "created_at": event.created_at,
                    "previous_hash": previous,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if (
                event.previous_hash != previous
                or event.event_hash != hashlib.sha256(material.encode()).hexdigest()
            ):
                return False
            previous = event.event_hash
        return True
