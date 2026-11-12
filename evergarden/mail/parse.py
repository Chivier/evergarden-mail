"""Tolerant MIME header and body parsing for archived mail.

- Decode RFC 2047 encoded-words in headers (Subject/From/To).
- Keep the first text/plain and the first text/html alternative; derive plain
  text from HTML only when no plain alternative exists.
- Never raise on broken or unusual messages.

The archive's stable message identity is derived from the values this module
produces, so changing how a header or date is normalized changes the identity
of already archived mail. Treat the output as a compatibility contract.
"""

from __future__ import annotations

import datetime as dt
import email
import email.header
import email.policy
import email.utils
import html
import re
from dataclasses import dataclass, field
from email.message import Message


def decode_header(value: str | None) -> str:
    if not value:
        return ""
    parts = email.header.decode_header(value)
    out = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            try:
                out.append(chunk.decode(enc or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                out.append(chunk.decode("utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out)


_TAG = re.compile(r"<[^>]+>")
_SCRIPT_STYLE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.I | re.S)


def html_to_text(value: str) -> str:
    """Naive HTML strip: drop script/style, drop tags, decode entities, collapse ws."""
    value = _SCRIPT_STYLE.sub(" ", value)
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.I)
    value = re.sub(r"</p>", "\n\n", value, flags=re.I)
    value = re.sub(r"</?(div|tr|li)[^>]*>", "\n", value, flags=re.I)
    value = _TAG.sub("", value)
    value = html.unescape(value)
    # Collapse runs of blank lines but preserve paragraph breaks.
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


@dataclass
class Attachment:
    filename: str
    mimetype: str
    size: int


@dataclass
class Parsed:
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    is_html_only: bool = False

    @property
    def from_(self) -> str:
        return self.headers.get("from", "")

    @property
    def to(self) -> str:
        return self.headers.get("to", "")

    @property
    def cc(self) -> str:
        return self.headers.get("cc", "")

    @property
    def subject(self) -> str:
        return self.headers.get("subject", "")

    @property
    def date(self) -> str:
        return self.headers.get("date", "")

    @property
    def message_id(self) -> str:
        return self.headers.get("message-id", "")

    @property
    def references(self) -> str:
        return self.headers.get("references", "")

    @property
    def in_reply_to(self) -> str:
        return self.headers.get("in-reply-to", "")


_FOLDED_DATE = re.compile(r"^Date:\s*(.+)$", re.I | re.S)


def _recover_folded_date(parsed: Parsed) -> None:
    """Undo an empty Subject that swallowed the following Date header.

    Some gateways emit `Subject:` with no value; the next line is then read as
    a folded continuation, so the Subject becomes the literal text
    "Date: Fri, 4 Oct 2024 14:47:49 +0100" and the message is left with no
    Date at all. Only rewrite when there is genuinely no Date header and the
    captured text parses as a real one, so a message actually titled "Date: …"
    is never touched.
    """
    if parsed.headers.get("date"):
        return
    match = _FOLDED_DATE.match(parsed.headers.get("subject", "").strip())
    if not match:
        return
    candidate = match.group(1).strip()
    try:
        if email.utils.parsedate_to_datetime(candidate) is None:
            return
    except (TypeError, ValueError):
        return
    parsed.headers["date"] = candidate
    parsed.headers["subject"] = ""


_KEEP_HEADERS = (
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "date",
    "message-id",
    "in-reply-to",
    "references",
    "reply-to",
    "list-id",
    "list-unsubscribe",
    "auto-submitted",
)


def _decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def parse_message(raw: bytes) -> Parsed:
    msg: Message = email.message_from_bytes(raw, policy=email.policy.default)
    parsed = Parsed()

    for name in _KEEP_HEADERS:
        value = msg.get(name)
        if value is not None:
            parsed.headers[name] = decode_header(str(value))

    _recover_folded_date(parsed)

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disposition = (part.get("Content-Disposition") or "").lower()
            content_type = part.get_content_type()
            if "attachment" in disposition or (
                content_type not in ("text/plain", "text/html") and part.get_filename()
            ):
                filename = decode_header(part.get_filename() or "(unnamed)")
                payload = part.get_payload(decode=True) or b""
                parsed.attachments.append(
                    Attachment(filename=filename, mimetype=content_type, size=len(payload))
                )
                continue
            body = _decode_payload(part)
            if content_type == "text/plain" and not parsed.text:
                parsed.text = body
            elif content_type == "text/html" and not parsed.html:
                parsed.html = body
    else:
        body = _decode_payload(msg)
        if msg.get_content_type() == "text/html":
            parsed.html = body
        else:
            parsed.text = body

    if not parsed.text and parsed.html:
        parsed.text = html_to_text(parsed.html)
        parsed.is_html_only = True

    return parsed


def address_email(value: str | None) -> str:
    """Lower-cased address from a From-style header, or "" when there is none."""
    if not value:
        return ""
    match = re.search(r"<([^>]+)>", value)
    if match:
        return match.group(1).strip().lower()
    value = value.strip().lower()
    if "@" in value and " " not in value:
        return value
    return ""


def address_name(value: str | None) -> str:
    """Display name from a From-style header, falling back to the local part."""
    if not value:
        return ""
    match = re.match(r'^\s*"?([^"<]+?)"?\s*<', value)
    if match:
        return match.group(1).strip().strip('"')
    if "@" in value:
        return value.split("@", 1)[0]
    return value.strip()


# parsedate_to_datetime happily returns absurd years for malformed headers
# (a real message parsed to the year 2611). Such a value sorts above every
# genuine message in a DESC scan, so treat it as unparseable instead.
_MIN_PLAUSIBLE_YEAR = 1990
_MAX_YEARS_AHEAD = 1


def date_to_iso(date_header: str | None) -> str:
    """Normalize a Date header to UTC ISO-8601 seconds, or "" when implausible."""
    if not date_header:
        return ""
    try:
        value = email.utils.parsedate_to_datetime(date_header)
        if value is None:
            return ""
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.UTC)
        value = value.astimezone(dt.UTC)
        if not _year_is_plausible(value):
            return ""
        return value.isoformat(timespec="seconds")
    except Exception:
        return ""


def _year_is_plausible(value: dt.datetime) -> bool:
    now = dt.datetime.now(dt.UTC)
    return _MIN_PLAUSIBLE_YEAR <= value.year <= now.year + _MAX_YEARS_AHEAD
