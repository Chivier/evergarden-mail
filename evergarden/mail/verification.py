from __future__ import annotations

import datetime as dt
import re
from typing import Any

from evergarden.archive.sqlite_archive import ArchiveReader

_CONTEXT = (
    r"security\s+(?:code|passcode)|verification\s+(?:code|passcode)|"
    r"one[- ]?time\s+(?:code|passcode|password)|login\s+code|sign[- ]?in\s+code|"
    r"authentication\s+code|(?:code|passcode)\s+is|otp|验证码|校验码|認証コード"
)
_CODE_AFTER = re.compile(rf"(?is)(?:{_CONTEXT}).{{0,80}}?(?<!\d)(\d{{4,8}})(?!\d)")
_CODE_BEFORE = re.compile(rf"(?is)(?<!\d)(\d{{4,8}})(?!\d).{{0,50}}?(?:{_CONTEXT})")
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    re.I,
)


class VerificationCodeError(RuntimeError):
    pass


def _received_at(value: object) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or dt.UTC).astimezone(dt.UTC)


def _sender_domain(address: object) -> str:
    raw = str(address or "").strip().casefold()
    return raw.rsplit("@", 1)[-1] if "@" in raw else ""


def _extract(text: str) -> list[str]:
    matches = [*(_CODE_AFTER.finditer(text)), *(_CODE_BEFORE.finditer(text))]
    return list(dict.fromkeys(match.group(1) for match in matches))[:3]


def find_verification_codes(
    archive: ArchiveReader,
    *,
    account: str | None,
    sender_domain: str | None,
    minutes: int,
    limit: int,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Read only recent, context-bound codes; never follows links or submits a code."""
    if not 1 <= minutes <= 60 or not 1 <= limit <= 20:
        raise VerificationCodeError("verification-code search bounds are invalid")
    requested_domain = str(sender_domain or "").strip().casefold().lstrip("@")
    if requested_domain and not _DOMAIN.fullmatch(requested_domain):
        raise VerificationCodeError("sender domain filter is malformed")
    current = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
    cutoff = current - dt.timedelta(minutes=minutes)
    candidates = archive.recent_verification_material(
        account=account,
        since=cutoff.isoformat(timespec="seconds"),
        limit=min(100, max(limit * 5, 20)),
    )
    found: list[dict[str, Any]] = []
    for candidate in candidates:
        received = _received_at(candidate.get("date_received"))
        if received is None or received < cutoff or received > current + dt.timedelta(minutes=5):
            continue
        domain = _sender_domain(candidate.get("sender_email"))
        if requested_domain and not (
            domain == requested_domain or domain.endswith(f".{requested_domain}")
        ):
            continue
        text = f"{candidate.get('subject') or ''}\n{candidate.get('body_text') or ''}"
        codes = _extract(text)
        if not codes:
            continue
        found.append(
            {
                "message_id": candidate["id"],
                "account": candidate["account"],
                "sender_domain": domain,
                "subject": candidate.get("subject") or "",
                "date_received": candidate.get("date_received"),
                "codes": codes,
            }
        )
        if len(found) >= limit:
            break
    return {
        "sensitive": True,
        "read_only": True,
        "automatic_submission": False,
        "window_minutes": minutes,
        "matches": found,
    }
