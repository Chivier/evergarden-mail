"""Tool schemas and argument validation for the MCP surface."""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

from evergarden.mail.attachments import MAX_DOWNLOAD_BYTES
from evergarden.mail.diagnostics import LOCATION_STATUSES
from evergarden.mail.preferences import (
    MAX_DESCRIPTION_CHARS,
    MAX_GLOBAL_NOTES_CHARS,
    MAX_PREFERENCES_CHARS,
)
from evergarden.mail.staged_attachments import MAX_BASE64_CHARS, STAGED_ATTACHMENT_ID


def _schema(properties: dict, *, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


ACCOUNT_FILTER = {"type": ["string", "null"]}
MESSAGE_ID = {"type": "string", "pattern": "^[0-9a-f]{24}$"}
ATTACHMENT_ID = {"type": "string", "pattern": "^[0-9a-f]{20}$"}
SOURCE_FOLDER = {"type": ["string", "null"], "minLength": 1, "maxLength": 255}
UUID_VALUE = {
    "type": "string",
    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
}
ADDRESS_LIST = {
    "type": "array",
    "items": {"type": "string", "minLength": 3, "maxLength": 320},
    "maxItems": 50,
}
ATTACHMENT_REFS = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "message_id": MESSAGE_ID,
            "attachment_id": ATTACHMENT_ID,
            "staged_attachment_id": {
                "type": "string",
                "pattern": STAGED_ATTACHMENT_ID.pattern,
            },
        },
        "required": [],
        "additionalProperties": False,
    },
    "maxItems": 20,
}
_MARK_ACTIONS = frozenset({"seen", "unseen", "flag", "unflag"})


def _schema_type_matches(value: object, expected: str) -> bool:
    return {
        "null": value is None,
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(expected, False)


def _validate_schema_value(value: object, schema: dict[str, Any], *, path: str) -> None:
    expected = schema.get("type")
    types = expected if isinstance(expected, list) else [expected]
    if expected is not None and not any(_schema_type_matches(value, item) for item in types):
        raise ValueError(f"{path} has the wrong type")
    if value is None:
        return
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} is not an allowed value")
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise ValueError(f"{path} is too short")
        if len(value) > int(schema.get("maxLength", len(value))):
            raise ValueError(f"{path} is too long")
        if pattern := schema.get("pattern"):
            # Python's `$` also matches before a trailing newline; anchor with
            # \Z so an anchored schema pattern enforces its advertised bound.
            anchored = rf"(?:{pattern})\Z" if str(pattern).endswith("$") else str(pattern)
            if not re.search(anchored, value):
                raise ValueError(f"{path} has an invalid format")
        if schema.get("format") == "date-time":
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"{path} must be an RFC 3339 timestamp") from exc
            # A timestamp without an offset is read as UTC (see normalize_timestamps).
            del parsed
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < int(schema["minimum"]):
            raise ValueError(f"{path} is below the minimum")
        if "maximum" in schema and value > int(schema["maximum"]):
            raise ValueError(f"{path} is above the maximum")
    if isinstance(value, list):
        if len(value) > int(schema.get("maxItems", len(value))):
            raise ValueError(f"{path} contains too many items")
        if len(value) < int(schema.get("minItems", 0)):
            raise ValueError(f"{path} contains too few items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema_value(item, item_schema, path=f"{path}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            missing = sorted(set(schema.get("required", [])) - set(value))
            if missing:
                raise ValueError(f"{path} is missing required fields: {', '.join(missing)}")
            if schema.get("additionalProperties") is False:
                unexpected = sorted(set(value) - set(properties))
                if unexpected:
                    raise ValueError(f"{path} has unexpected fields: {', '.join(unexpected)}")
            for key, item in value.items():
                if key in properties:
                    _validate_schema_value(item, properties[key], path=f"{path}.{key}")


TOOL_DEFINITIONS: dict[str, dict[str, Any]] = {
    "service_info": {
        "description": "Describe the Evergarden security boundary without revealing credentials.",
        "inputSchema": _schema({}),
    },
    "health_status": {
        "description": "Return content-free service and archive health.",
        "inputSchema": _schema({}),
    },
    "list_accounts": {
        "description": (
            "List configured mailbox aliases, addresses, and non-destructive folder actions; "
            "never credentials."
        ),
        "inputSchema": _schema({}),
    },
    "list_folders": {
        "description": "List observed folder counts without message content.",
        "inputSchema": _schema({"account": ACCOUNT_FILTER}),
    },
    "sync_status": {
        "description": "Return per-folder read-only sync watermarks and timestamps.",
        "inputSchema": _schema({"account": ACCOUNT_FILTER}),
    },
    "sync_mail": {
        "description": "Trigger a bounded read-only provider sync; no mailbox mutation is issued.",
        "inputSchema": _schema(
            {
                "account": ACCOUNT_FILTER,
                "per_folder_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5000,
                    "default": 500,
                },
            }
        ),
    },
    "oauth_status": {
        "description": "Return token readiness metadata without exposing any provider token.",
        "inputSchema": _schema({}),
    },
    "find_verification_codes": {
        "description": (
            "Read recent context-bound verification codes. Never follows links, submits a code, "
            "or bypasses provider MFA."
        ),
        "inputSchema": _schema(
            {
                "account": ACCOUNT_FILTER,
                "sender_domain": {
                    "type": ["string", "null"],
                    "minLength": 1,
                    "maxLength": 253,
                },
                "minutes": {"type": "integer", "minimum": 1, "maximum": 60, "default": 15},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
            }
        ),
    },
    "get_mail_preferences": {
        "description": "Read encrypted global notes and per-mailbox descriptions/preferences.",
        "inputSchema": _schema({}),
    },
    "edit_global_notes": {
        "description": "Revision-checked edit of encrypted global mail notes; never Git-backed.",
        "inputSchema": _schema(
            {
                "expected_revision": {"type": "integer", "minimum": 0},
                "notes": {"type": "string", "maxLength": MAX_GLOBAL_NOTES_CHARS},
            },
            required=["expected_revision", "notes"],
        ),
    },
    "edit_mailbox_preferences": {
        "description": "Edit one encrypted mailbox description and preference note.",
        "inputSchema": _schema(
            {
                "account": {"type": "string", "minLength": 1, "maxLength": 64},
                "expected_revision": {"type": "integer", "minimum": 0},
                "description": {"type": "string", "maxLength": MAX_DESCRIPTION_CHARS},
                "preferences": {"type": "string", "maxLength": MAX_PREFERENCES_CHARS},
            },
            required=["account", "expected_revision", "description", "preferences"],
        ),
    },
    "list_recent": {
        "description": "List recent archived mail metadata; message bodies are omitted.",
        "inputSchema": _schema(
            {
                "account": ACCOUNT_FILTER,
                "folder": {"type": ["string", "null"]},
                "inbox_only": {"type": "boolean", "default": False},
                "since": {"type": ["string", "null"], "format": "date-time"},
                "before": {"type": ["string", "null"], "format": "date-time"},
                "unread_only": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                "actionable_only": {"type": "boolean", "default": False},
                "location_status": {"type": ["string", "null"], "enum": [*LOCATION_STATUSES, None]},
                "paginated": {"type": "boolean", "default": False},
                "cursor": {"type": ["string", "null"], "maxLength": 2048},
            }
        ),
    },
    "list_sent_metadata": {
        "description": (
            "Read bounded live Sent header metadata through Evergarden without returning bodies "
            "or changing provider/archive state."
        ),
        "inputSchema": _schema(
            {
                "account": ACCOUNT_FILTER,
                "since": {"type": "string", "format": "date-time"},
                "per_account_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 100,
                },
            },
            required=["since"],
        ),
    },
    "count_mail": {
        "description": "Count indexed, actionable, location-anomalous and unverified mail separately using identical list filters. Use inbox_only and unread_only for unread Inbox counts.",
        "inputSchema": _schema(
            {
                "account": ACCOUNT_FILTER,
                "folder": {"type": ["string", "null"], "maxLength": 255},
                "inbox_only": {"type": "boolean", "default": False},
                "since": {"type": ["string", "null"], "format": "date-time"},
                "before": {"type": ["string", "null"], "format": "date-time"},
                "unread_only": {"type": "boolean", "default": False},
                "actionable_only": {"type": "boolean", "default": False},
                "location_status": {"type": ["string", "null"], "enum": [*LOCATION_STATUSES, None]},
            }
        ),
    },
    "search_mail": {
        "description": "Full-text search archived mail and return redacted snippets.",
        "inputSchema": _schema(
            {
                "query": {"type": "string", "minLength": 1, "maxLength": 500},
                "account": ACCOUNT_FILTER,
                "folder": {"type": ["string", "null"]},
                "since": {"type": ["string", "null"], "format": "date-time"},
                "before": {"type": ["string", "null"], "format": "date-time"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            required=["query"],
        ),
    },
    "get_message": {
        "description": "Read one archived message as sanitized text; HTML is never returned.",
        "inputSchema": _schema({"message_id": MESSAGE_ID}, required=["message_id"]),
    },
    "get_thread": {
        "description": "Read a bounded sanitized thread linked by standard message headers.",
        "inputSchema": _schema(
            {
                "message_id": MESSAGE_ID,
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 100},
            },
            required=["message_id"],
        ),
    },
    "mailbox_stats": {
        "description": "Return archive counts and shard names without message content.",
        "inputSchema": _schema({}),
    },
    "list_attachments": {
        "description": "List attachment metadata and safe-download availability.",
        "inputSchema": _schema({"message_id": MESSAGE_ID}, required=["message_id"]),
    },
    "download_attachment": {
        "description": "Return one allowlisted attachment as bounded base64 without opening it.",
        "inputSchema": _schema(
            {
                "message_id": MESSAGE_ID,
                "attachment_id": ATTACHMENT_ID,
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_DOWNLOAD_BYTES,
                    "default": MAX_DOWNLOAD_BYTES,
                },
            },
            required=["message_id", "attachment_id"],
        ),
    },
    "stage_attachment": {
        "description": (
            "Validate and encrypt one bounded local attachment for an outbound review packet. "
            "The returned opaque reference expires and contains no provider credential."
        ),
        "inputSchema": _schema(
            {
                "filename": {"type": "string", "minLength": 1, "maxLength": 1024},
                "mimetype": {"type": "string", "minLength": 3, "maxLength": 255},
                "content_base64": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_BASE64_CHARS,
                },
            },
            required=["filename", "mimetype", "content_base64"],
        ),
    },
    "get_draft_status": {
        "description": (
            "Return one immutable draft, human-approval state, and execution state. "
            "Only the client that prepared it may read it."
        ),
        "inputSchema": _schema({"draft_id": UUID_VALUE}, required=["draft_id"]),
    },
    "prepare_send": {
        "description": (
            "Prepare an immutable outbound review packet. This never sends. The result reports "
            "whether an approval was issued automatically or a human approval is still required."
        ),
        "inputSchema": _schema(
            {
                "account": {"type": "string"},
                "from": {"type": ["string", "null"]},
                "to": ADDRESS_LIST,
                "cc": ADDRESS_LIST,
                "bcc": ADDRESS_LIST,
                "subject": {"type": "string", "minLength": 1, "maxLength": 998},
                "body": {"type": "string", "minLength": 1, "maxLength": 100000},
                "attachments": ATTACHMENT_REFS,
            },
            required=["account", "to", "subject", "body"],
        ),
    },
    "prepare_reply": {
        "description": (
            "Prepare a server-derived reply review packet. This never sends; send_approved does."
        ),
        "inputSchema": _schema(
            {
                "message_id": MESSAGE_ID,
                "body": {"type": "string", "minLength": 1, "maxLength": 100000},
                "cc": ADDRESS_LIST,
                "reply_all": {"type": "boolean", "default": False},
                "attachments": ATTACHMENT_REFS,
            },
            required=["message_id", "body"],
        ),
    },
    "prepare_forward": {
        "description": (
            "Prepare a sanitized forward review packet. This never sends; send_approved does."
        ),
        "inputSchema": _schema(
            {
                "message_id": MESSAGE_ID,
                "to": ADDRESS_LIST,
                "cc": ADDRESS_LIST,
                "body": {"type": ["string", "null"], "maxLength": 100000},
                "attachments": ATTACHMENT_REFS,
            },
            required=["message_id", "to"],
        ),
    },
    "send_approved": {
        "description": (
            "Send the prepared packet by consuming its approval exactly once. Use the approval_id "
            "returned by prepare_*; runtime writer fences still apply."
        ),
        "inputSchema": _schema(
            {
                "approval_id": UUID_VALUE,
                "draft_id": UUID_VALUE,
                "payload": {"type": "object"},
            },
            required=["approval_id", "draft_id", "payload"],
        ),
    },
    "preview_archive": {
        "description": (
            "Prepare an allowlisted Archive intent after a read-only provider capability check. "
            "If copy_preserve_source_fallback is true and native MOVE is unavailable, execution "
            "copies to Archive and marks the retained source Seen; it does not remove the source. "
            "Accounts configured for UIDPLUS move remove the source after a verified copy."
        ),
        "inputSchema": _schema(
            {
                "account": {"type": "string"},
                "stable_message_id": MESSAGE_ID,
                "destination": {"type": "string"},
                "source_folder": SOURCE_FOLDER,
            },
            required=["account", "stable_message_id"],
        ),
    },
    "archive_approved": {
        "description": (
            "Execute a prepared Archive by consuming its approval exactly once; "
            "runtime writer fences still apply."
        ),
        "inputSchema": _schema(
            {
                "approval_id": UUID_VALUE,
                "draft_id": UUID_VALUE,
                "payload": {"type": "object"},
            },
            required=["approval_id", "draft_id", "payload"],
        ),
    },
    "preview_move_unrelated": {
        "description": "Prepare a move to the sole allowed Unrelated destination without executing it.",
        "inputSchema": _schema(
            {
                "account": {"type": "string"},
                "stable_message_id": MESSAGE_ID,
                "source_folder": SOURCE_FOLDER,
            },
            required=["account", "stable_message_id"],
        ),
    },
    "preview_move": {
        "description": (
            "Prepare an allowlisted same-account folder move after a read-only capability check. "
            "Configured copy_preserve_source_fallback preserves the source and marks it Seen "
            "when native MOVE is unavailable. Accounts configured for UIDPLUS move remove the "
            "source after a verified copy."
        ),
        "inputSchema": _schema(
            {
                "account": {"type": "string"},
                "stable_message_id": MESSAGE_ID,
                "destination": {"type": "string", "minLength": 1, "maxLength": 255},
                "source_folder": SOURCE_FOLDER,
            },
            required=["account", "stable_message_id", "destination"],
        ),
    },
    "move_approved": {
        "description": (
            "Execute a prepared allowlisted move by consuming its approval exactly once. "
            "Runtime fencing still applies."
        ),
        "inputSchema": _schema(
            {
                "approval_id": UUID_VALUE,
                "draft_id": UUID_VALUE,
                "payload": {"type": "object"},
            },
            required=["approval_id", "draft_id", "payload"],
        ),
    },
    "preview_mark": {
        "description": "Prepare a reversible seen/unseen/flag/unflag change without executing it.",
        "inputSchema": _schema(
            {
                "account": {"type": "string"},
                "stable_message_id": MESSAGE_ID,
                "action": {"type": "string", "enum": ["seen", "unseen", "flag", "unflag"]},
                "source_folder": SOURCE_FOLDER,
            },
            required=["account", "stable_message_id", "action"],
        ),
    },
    "mark_approved": {
        "description": (
            "Execute a prepared reversible flag change by consuming its approval exactly once. "
            "Runtime fencing applies."
        ),
        "inputSchema": _schema(
            {
                "approval_id": UUID_VALUE,
                "draft_id": UUID_VALUE,
                "payload": {"type": "object"},
            },
            required=["approval_id", "draft_id", "payload"],
        ),
    },
    "preview_trash": {
        "description": (
            "Prepare a reversible move to the configured Trash folder. Accounts without IMAP "
            "MOVE that are configured for UIDPLUS move copy to Trash, verify the copy, then "
            "UID-EXPUNGE only that source message. Never deletes permanently."
        ),
        "inputSchema": _schema(
            {
                "account": {"type": "string", "minLength": 1, "maxLength": 64},
                "stable_message_id": MESSAGE_ID,
                "source_folder": SOURCE_FOLDER,
            },
            required=["account", "stable_message_id"],
        ),
    },
    "trash_approved": {
        "description": (
            "Consume a human approval for a move to configured Trash (native MOVE or configured "
            "UIDPLUS move). The server dispatcher normally executes human approvals itself."
        ),
        "inputSchema": _schema(
            {
                "approval_id": UUID_VALUE,
                "draft_id": UUID_VALUE,
                "payload": {"type": "object"},
            },
            required=["approval_id", "draft_id", "payload"],
        ),
    },
    "move_unrelated_approved": {
        "description": (
            "Execute a prepared Unrelated move by consuming its approval exactly once; "
            "runtime writer fences still apply."
        ),
        "inputSchema": _schema(
            {
                "approval_id": UUID_VALUE,
                "draft_id": UUID_VALUE,
                "payload": {"type": "object"},
            },
            required=["approval_id", "draft_id", "payload"],
        ),
    },
    "mail_operations_status": {
        "description": "Return content-free mail job, action-ledger and writer-fence status.",
        "inputSchema": _schema({}),
    },
    "diagnose_message": {
        "description": "Read content-free provider snapshot, UID/UIDVALIDITY, sync and operation evidence. Missing location never means archived/deleted. Does not contact or modify provider mail.",
        "inputSchema": _schema({"stable_message_id": MESSAGE_ID}, required=["stable_message_id"]),
    },
    "submit_mail_feedback": {
        "description": "Record a deduplicated location issue and user's intended decision. This never grants approval or executes mail actions; confirmed execution cannot be self-reported.",
        "inputSchema": _schema(
            {
                "stable_message_id": MESSAGE_ID,
                "intended_action": {"type": "string", "enum": ["archive", "trash", "move", "mark"]},
                "user_decision": {"type": "string", "enum": ["authorized", "pending", "rejected"]},
                "processing_status": {
                    "type": "string",
                    "enum": ["pending_approval", "blocked", "unknown"],
                },
                "reason_code": {"type": "string", "minLength": 1, "maxLength": 80},
            },
            required=[
                "stable_message_id",
                "intended_action",
                "user_decision",
                "processing_status",
                "reason_code",
            ],
        ),
    },
    "get_mail_feedback": {
        "description": "Read an issue, decision history and current recovery/execution evidence.",
        "inputSchema": _schema({"issue_id": UUID_VALUE}, required=["issue_id"]),
    },
    "list_mail_feedback": {
        "description": "List feedback issues; restored_only discovers recovered actionable messages requiring fresh approval.",
        "inputSchema": _schema(
            {
                "restored_only": {"type": "boolean", "default": False},
                "cursor": {"type": ["string", "null"], "maxLength": 36},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            }
        ),
    },
}
