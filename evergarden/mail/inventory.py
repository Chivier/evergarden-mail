from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any


def canonical_date(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value[:19]
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC).isoformat(timespec="seconds")


def inventory_message_row(
    *,
    stable_id: object,
    account: object,
    folder: object,
    message_id: object,
    date_received: object,
    sender_email: object,
    subject: object,
    raw_size: object,
) -> dict[str, str | int]:
    """Build the content-free evidence row that identifies one archived message."""
    account_text = str(account or "")
    date_text = canonical_date(str(date_received or ""))
    size = int(raw_size or 0)
    fingerprint = hashlib.sha256(
        "\0".join(
            [
                account_text.lower(),
                str(sender_email or "").lower(),
                date_text,
                str(subject or "").strip().lower(),
                str(size),
            ]
        ).encode()
    ).hexdigest()
    return {
        "stable_id": str(stable_id),
        "account": account_text,
        "folder": str(folder or ""),
        "message_id_hash": hashlib.sha256(
            str(message_id or "").strip().lower().encode()
        ).hexdigest(),
        "normalized_date": date_text,
        "fallback_fingerprint": fingerprint,
        "raw_size": size,
    }


def inventory_row_from_mapping(row: Any) -> dict[str, str | int]:
    return inventory_message_row(
        stable_id=row["id"],
        account=row["account"],
        folder=row["folder"],
        message_id=row["message_id"],
        date_received=row["date_received"],
        sender_email=row["sender_email"],
        subject=row["subject"],
        raw_size=row["raw_size"],
    )


def inventory_row_from_record(record: Any) -> dict[str, str | int]:
    return inventory_message_row(
        stable_id=record.stable_id,
        account=record.account,
        folder=record.folder,
        message_id=record.message_id,
        date_received=record.date_received,
        sender_email=record.sender_email,
        subject=record.subject,
        raw_size=record.raw_size,
    )
