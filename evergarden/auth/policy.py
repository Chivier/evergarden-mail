from __future__ import annotations

from collections.abc import Iterable

from evergarden.auth.models import InsufficientScope, Principal

TOOL_SCOPES: dict[str, frozenset[str]] = {
    "service_info": frozenset({"mail:metadata"}),
    "health_status": frozenset({"mail:metadata"}),
    "list_accounts": frozenset({"mail:metadata"}),
    "list_folders": frozenset({"mail:metadata"}),
    "sync_status": frozenset({"mail:metadata"}),
    "sync_mail": frozenset({"mail:sync"}),
    "oauth_status": frozenset({"mail:metadata"}),
    "find_verification_codes": frozenset({"mail:verification"}),
    "get_mail_preferences": frozenset({"mail:settings"}),
    "edit_global_notes": frozenset({"mail:settings"}),
    "edit_mailbox_preferences": frozenset({"mail:settings"}),
    "list_recent": frozenset({"mail:metadata"}),
    "list_sent_metadata": frozenset({"mail:metadata"}),
    "count_mail": frozenset({"mail:metadata"}),
    "diagnose_message": frozenset({"mail:metadata"}),
    "submit_mail_feedback": frozenset({"mail:metadata"}),
    "get_mail_feedback": frozenset({"mail:metadata"}),
    "list_mail_feedback": frozenset({"mail:metadata"}),
    "mailbox_stats": frozenset({"mail:metadata"}),
    "search_mail": frozenset({"mail:read"}),
    "get_message": frozenset({"mail:read"}),
    "get_thread": frozenset({"mail:read"}),
    "list_attachments": frozenset({"mail:attachments"}),
    "download_attachment": frozenset({"mail:attachments"}),
    "stage_attachment": frozenset({"mail:attachments"}),
    "get_draft_status": frozenset({"mail:draft"}),
    "prepare_send": frozenset({"mail:draft"}),
    "prepare_reply": frozenset({"mail:read", "mail:draft"}),
    "prepare_forward": frozenset({"mail:read", "mail:draft"}),
    "send_approved": frozenset({"mail:send-approved"}),
    "preview_archive": frozenset({"mail:organize"}),
    "archive_approved": frozenset({"mail:organize"}),
    "preview_move_unrelated": frozenset({"mail:organize"}),
    "move_unrelated_approved": frozenset({"mail:organize"}),
    "preview_move": frozenset({"mail:organize"}),
    "move_approved": frozenset({"mail:organize"}),
    "preview_mark": frozenset({"mail:organize"}),
    "mark_approved": frozenset({"mail:organize"}),
    "preview_trash": frozenset({"mail:delete"}),
    "trash_approved": frozenset({"mail:delete"}),
    "mail_operations_status": frozenset({"mail:operations"}),
}

# No approve tool exists. An MCP client never approves on demand: approvals are
# either issued at preparation time by EVERGARDEN_AUTO_APPROVE policy, or by a
# human on the approval surface. Trash is always the latter.
FORBIDDEN_TOOL_NAMES = frozenset({"delete", "trash", "expunge", "approve", "move_to_trash"})


def require_scopes(principal: Principal, required: Iterable[str]) -> None:
    missing = sorted(set(required) - principal.scopes)
    if missing:
        raise InsufficientScope(" ".join(missing))


def require_scope(principal: Principal, required: str) -> None:
    require_scopes(principal, {required})


def visible_tools(principal: Principal, available: Iterable[str]) -> list[str]:
    return sorted(
        name
        for name in available
        if name not in FORBIDDEN_TOOL_NAMES
        and (required := TOOL_SCOPES.get(name)) is not None
        and required <= principal.scopes
    )


def supported_scopes() -> list[str]:
    return sorted({scope for required in TOOL_SCOPES.values() for scope in required})
