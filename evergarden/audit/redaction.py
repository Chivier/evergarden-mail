from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any

SECRET_KEY_RE = re.compile(
    r"(?i)(access.?token|refresh.?token|authorization|password|client.?secret|"
    r"credential|cookie|session|app.?password|smtp.?password)"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}|"
    r"((?:(?:access|refresh)[_-]?token|(?:app|smtp)[_-]?password|password|"
    r"client[_-]?secret|cookie|authorization)\s*[:=]\s*)\S+"
)
VERIFICATION_CODE_RE = re.compile(
    r"(?i)((?:security|verification|one[- ]?time|login|sign[- ]?in|authentication)\s+"
    r"(?:code|passcode|password)|(?:code|passcode)\s+is|otp|验证码|校验码|認証コード)"
    r"(\s*(?:is|:|：|-)?\s*)\d{4,8}"  # noqa: RUF001 - full-width punctuation is mail text
)
ADDRESS_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
ERROR_DETAIL_LIMIT = 200


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


def redact_text(value: str) -> str:
    redacted = SECRET_VALUE_RE.sub(
        lambda match: f"{match.group(1) or match.group(2)}[REDACTED]", value
    )
    return VERIFICATION_CODE_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", redacted
    )


def redact_error_detail(value: Any, *, limit: int = ERROR_DETAIL_LIMIT) -> str:
    """Bound a provider/IMAP error string for a private report or log line.

    Diagnosing a failed sync needs the provider's own wording, but that wording
    may quote a mailbox address. Secrets, verification codes and addresses are
    removed and the remainder is truncated.
    """
    text = ADDRESS_RE.sub("[ADDRESS]", redact_text(str(value))).strip()
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if SECRET_KEY_RE.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def safe_json(value: Any) -> str:
    return json.dumps(redact(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(str(record.msg))
        if record.args:
            record.args = (
                tuple(redact(arg) for arg in record.args)
                if isinstance(record.args, tuple)
                else redact(record.args)
            )
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
