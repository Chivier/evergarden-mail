from __future__ import annotations

import contextlib
import copy
import datetime as dt
import re
import threading
import uuid
from collections.abc import Callable
from email.utils import getaddresses
from typing import Any, ClassVar

from evergarden.approvals.models import Actor, IntentKind
from evergarden.approvals.service import ApprovalService, ProviderNotAttempted
from evergarden.archive.sqlite_archive import ArchiveReader
from evergarden.auth.models import Principal
from evergarden.mail.attachments import MAX_DOWNLOAD_BYTES
from evergarden.mail.diagnostics import (
    LocationActionBlocked,
    LocationEvidenceCache,
    LocationSnapshot,
)
from evergarden.mail.feedback import FeedbackStore
from evergarden.mail.models import AccountConfig, normalize_message_id
from evergarden.mail.preferences import (
    MailPreferenceStore,
)
from evergarden.mail.staged_attachments import (
    StagedAttachmentStore,
)
from evergarden.mail.verification import find_verification_codes

# Re-exported for compatibility: tests and callers import these from here.
from evergarden.mcp.tool_definitions import (  # noqa: F401
    _MARK_ACTIONS,
    TOOL_DEFINITIONS,
    _schema_type_matches,
    _validate_schema_value,
)

_TIME_ARGUMENTS = ("since", "before")


def _naive_times_as_utc(arguments: dict[str, Any]) -> dict[str, Any]:
    """Read a ``since``/``before`` timestamp without an offset as UTC.

    Clients often send ``2026-11-01T00:00:00``; rejecting it only produced
    failed calls, and every archive filter already treats it as UTC.
    """
    fixed = dict(arguments)
    for key in _TIME_ARGUMENTS:
        value = fixed.get(key)
        if not isinstance(value, str) or not value:
            continue
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            fixed[key] = parsed.replace(tzinfo=dt.UTC).isoformat()
    return fixed


class ToolRuntime:
    def __init__(
        self,
        *,
        archive: ArchiveReader,
        approvals: ApprovalService,
        execute_approved: Callable[..., dict],
        accounts: tuple[AccountConfig, ...] = (),
        receive_only_accounts: frozenset[str] = frozenset(),
        mode: str = "read-only",
        side_effects_enabled: bool = False,
        trash_actions_enabled: bool = False,
        sync_provider: Callable[[str | None, int], list[dict]] | None = None,
        sent_metadata_provider: (
            Callable[[str | None, dt.datetime, dt.datetime, int], list[dict]] | None
        ) = None,
        oauth_status_provider: Callable[[], list[dict]] | None = None,
        preferences: MailPreferenceStore | None = None,
        staged_attachments: StagedAttachmentStore | None = None,
        operations_status_provider: Callable[[], dict] | None = None,
        organization_capabilities_provider: Callable[[str], dict] | None = None,
        now: Callable[[], dt.datetime] | None = None,
        feedback_base_url: str = "",
        uidplus_move_accounts: frozenset[str] = frozenset(),
        approval_dispatch_kinds: frozenset[IntentKind] = frozenset(),
        approval_session: Callable[[], contextlib.AbstractContextManager] = contextlib.nullcontext,
    ):
        self.receive_only_accounts = receive_only_accounts
        self.archive = archive
        self._location_evidence = LocationEvidenceCache(archive)
        self.approvals = approvals
        self.execute_approved = execute_approved
        # Scope in which the approval dispatcher reuses provider connections.
        self.approval_session = approval_session
        self.mode = mode
        self.side_effects_enabled = side_effects_enabled
        self.trash_actions_enabled = trash_actions_enabled
        self.sync_provider = sync_provider or (
            lambda _account, _limit: (_ for _ in ()).throw(
                RuntimeError("mail sync provider is not configured")
            )
        )
        self.sent_metadata_provider = sent_metadata_provider or (
            lambda _account, _since, _before, _limit: (_ for _ in ()).throw(
                RuntimeError("live Sent metadata provider is not configured")
            )
        )
        self.oauth_status_provider = oauth_status_provider or (lambda: [])
        self.preferences = preferences
        self.staged_attachments = staged_attachments
        self.operations_status_provider = operations_status_provider or (
            lambda: {"available": False, "reason": "status provider is not configured"}
        )
        self.now = now or (lambda: dt.datetime.now(dt.UTC))
        self.accounts = {account.alias: account for account in accounts}
        self.feedback_base_url = feedback_base_url
        self.organization_capabilities_provider = organization_capabilities_provider
        self.uidplus_move_accounts = frozenset(uidplus_move_accounts)
        self.approval_dispatch_kinds = frozenset(approval_dispatch_kinds)
        self._organization_capabilities_cache: dict[str, tuple[dt.datetime, dict | None]] = {}
        self._organization_capabilities_lock = threading.Lock()
        self._organization_capabilities_locks: dict[str, threading.Lock] = {}

    @property
    def feedback(self) -> FeedbackStore:
        return FeedbackStore(self.archive.data_dir)

    def location_snapshot(self) -> LocationSnapshot:
        return LocationSnapshot(
            self.archive,
            now=self.now(),
            executions=self.approvals.repository.location_execution_summaries(),
            base_url=self.feedback_base_url,
            evidence=self._location_evidence.get(),
        )

    def call(self, name: str, arguments: dict[str, Any], principal: Principal) -> Any:
        if not isinstance(arguments, dict):
            raise ValueError("tool arguments must be an object")
        self._validate_argument_shape(name, arguments)
        arguments = _naive_times_as_utc(arguments)
        if name in WRITE_PREPARE_KINDS:
            self._guard_write_target(name, arguments)
            actor = Actor(principal.subject, principal.client_id, "mcp", False)
            payload = self._WRITE_PAYLOADS[name](self, arguments)
            draft = self.approvals.prepare(
                kind=WRITE_PREPARE_KINDS[name], payload=payload, actor=actor
            )
            return self._draft_result(draft)
        if name in APPROVED_EXECUTION_KINDS:
            return self.execute_approved(
                approval_id=str(arguments.get("approval_id", "")),
                draft_id=str(arguments.get("draft_id", "")),
                current_payload=arguments.get("payload") or {},
                expected_kind=APPROVED_EXECUTION_KINDS[name],
            )
        handler = self._READ_HANDLERS.get(name)
        if handler is None:
            raise ValueError(f"unknown tool: {name}")
        return handler(self, arguments, principal)

    def _guard_write_target(self, name: str, arguments: dict[str, Any]) -> None:
        """Pre-draft checks for every write-preparing tool, by table, not by
        name prefix, so a new write tool cannot silently skip them."""
        alias = arguments.get("account")
        message_id = arguments.get("message_id") or arguments.get("stable_message_id")
        if message_id:
            # get_message raises on an unknown id; it never returns empty.
            alias = self.archive.get_message(message_id)["account"]
            # Key the location check on the intent table, not the tool name:
            # every organization kind needs a located message, only SEND
            # (reply/forward quote an archived message) does not.
            if WRITE_PREPARE_KINDS[name] is not IntentKind.SEND:
                state = self.location_snapshot().state(message_id)
                if (
                    state["location_status"]
                    in {
                        "missing",
                        "uidvalidity_changed",
                        "auth_failed",
                        "ambiguous",
                        "moved_confirmed",
                    }
                    or state["reason_code"] == "PROVIDER_OUTCOME_UNKNOWN"
                ):
                    raise LocationActionBlocked(state)
        if alias in self.receive_only_accounts:
            raise ValueError("This mailbox supports receiving and notifications only")

    def _tool_diagnose_message(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.location_snapshot().diagnose(str(arguments["stable_message_id"]))

    def _tool_submit_mail_feedback(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.feedback.submit(self.location_snapshot(), **arguments)

    def _tool_get_mail_feedback(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.feedback.get(self.location_snapshot(), str(arguments["issue_id"]))

    def _tool_list_mail_feedback(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.feedback.list(
            self.location_snapshot(),
            restored_only=bool(arguments.get("restored_only", False)),
            after=arguments.get("cursor"),
            limit=int(arguments.get("limit", 20)),
        )

    def _tool_service_info(self, _arguments: dict[str, Any], principal: Principal) -> Any:
        return {
            "name": "Evergarden Mail",
            "mode": self.mode,
            "resource": "OAuth-protected MCP",
            "client_id": principal.client_id,
            "capabilities": sorted(TOOL_DEFINITIONS),
            "explicitly_absent": ["approve", "permanent_delete", "expunge", "raw_proxy"],
            "auto_approved_intents": sorted(
                kind.value for kind in self.approvals.auto_approve_kinds
            ),
            "side_effects": "enabled" if self.side_effects_enabled else "fence-rejected",
            "reversible_trash": ("enabled" if self.trash_actions_enabled else "separately-fenced"),
            "token_passthrough": False,
        }

    def _tool_health_status(self, _arguments: dict[str, Any], _principal: Principal) -> Any:
        stats = self.archive.stats()
        return {
            "ok": True,
            "mode": self.mode,
            "archive_messages": stats["messages"],
            "archive_shards": stats["shards"],
            "external_side_effects": self.side_effects_enabled,
        }

    def _tool_list_accounts(self, _arguments: dict[str, Any], _principal: Principal) -> Any:
        return [
            {
                **({"receive_only": True} if account.alias in self.receive_only_accounts else {}),
                "alias": account.alias,
                "email": account.address,
                "default_from": account.default_from_address,
                "send_from_addresses": list(account.allowed_from_addresses),
                "archive_folder": account.archive_folder,
                "sent_folder": account.sent_folder,
                "trash_folder": account.trash_folder,
                "safe_move_folders": list(account.safe_move_folders),
                "copy_preserve_source_fallback": account.copy_preserve_source_fallback,
                "uidplus_move_fallback": account.alias in self.uidplus_move_accounts,
                "mark_actions": sorted(_MARK_ACTIONS),
            }
            for account in self.accounts.values()
        ]

    def _tool_list_folders(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.archive.list_folders(self._validate_account(arguments.get("account")))

    def _tool_sync_status(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        account = self._validate_account(arguments.get("account"))
        observed = {(item["account"], item["folder"]): item for item in self.archive.sync_status()}
        aliases = [account] if account else list(self.accounts)
        return [
            observed.get(
                (alias, folder),
                {
                    "account": alias,
                    "folder": folder,
                    "uid_validity": None,
                    "last_uid": None,
                    "last_synced_at": None,
                },
            )
            for alias in aliases
            for folder in dict.fromkeys(
                (
                    *self.accounts[alias].folders,
                    *(folder for observed_alias, folder in observed if observed_alias == alias),
                )
            )
        ]

    def _tool_sync_mail(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        account = self._validate_account(arguments.get("account"))
        return self.sync_provider(account, int(arguments.get("per_folder_limit", 500)))

    def _tool_oauth_status(self, _arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.oauth_status_provider()

    def _tool_find_verification_codes(
        self, arguments: dict[str, Any], _principal: Principal
    ) -> Any:
        return find_verification_codes(
            self.archive,
            account=self._validate_account(arguments.get("account")),
            sender_domain=arguments.get("sender_domain"),
            minutes=int(arguments.get("minutes", 15)),
            limit=int(arguments.get("limit", 5)),
            now=self.now(),
        )

    def _tool_get_mail_preferences(self, _arguments: dict[str, Any], _principal: Principal) -> Any:
        if self.preferences is None:
            raise RuntimeError("mail preference store is not configured")
        return self.preferences.get()

    def _tool_edit_global_notes(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        if self.preferences is None:
            raise RuntimeError("mail preference store is not configured")
        return self.preferences.edit_global_notes(
            expected_revision=int(arguments["expected_revision"]),
            notes=str(arguments["notes"]),
        )

    def _tool_edit_mailbox_preferences(
        self, arguments: dict[str, Any], _principal: Principal
    ) -> Any:
        if self.preferences is None:
            raise RuntimeError("mail preference store is not configured")
        account = self._validate_account(arguments["account"])
        if account is None:
            raise ValueError("a concrete mailbox is required")
        return self.preferences.edit_mailbox(
            account=account,
            expected_revision=int(arguments["expected_revision"]),
            description=str(arguments["description"]),
            preferences=str(arguments["preferences"]),
        )

    def _tool_list_recent(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        account = self._validate_account(arguments.get("account"))
        page = self.location_snapshot().page(
            account=account,
            folder=arguments.get("folder"),
            inbox_only=bool(arguments.get("inbox_only", False)),
            since=arguments.get("since"),
            before=arguments.get("before"),
            unread_only=bool(arguments.get("unread_only", False)),
            limit=int(arguments.get("limit", 20)),
            actionable_only=bool(arguments.get("actionable_only", False)),
            location_status=arguments.get("location_status"),
            cursor=arguments.get("cursor"),
        )
        return page if arguments.get("paginated") or arguments.get("cursor") else page["items"]

    def _tool_list_sent_metadata(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        account = self._validate_account(arguments.get("account"))
        since = dt.datetime.fromisoformat(str(arguments["since"]).replace("Z", "+00:00"))
        now = self.now().astimezone(dt.UTC)
        since_utc = since.astimezone(dt.UTC)
        if since_utc > now + dt.timedelta(minutes=5):
            raise ValueError("Sent metadata window cannot begin in the future")
        if now - since_utc > dt.timedelta(days=31):
            raise ValueError("Sent metadata window cannot exceed 31 days")
        return self.sent_metadata_provider(
            account,
            since_utc,
            now + dt.timedelta(seconds=1),
            int(arguments.get("per_account_limit", 100)),
        )

    def _tool_count_mail(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        account = self._validate_account(arguments.get("account"))
        return self.location_snapshot().counts(
            account=account,
            folder=arguments.get("folder"),
            inbox_only=bool(arguments.get("inbox_only", False)),
            since=arguments.get("since"),
            before=arguments.get("before"),
            unread_only=bool(arguments.get("unread_only", False)),
            actionable_only=bool(arguments.get("actionable_only", False)),
            location_status=arguments.get("location_status"),
        )

    def _tool_search_mail(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        account = self._validate_account(arguments.get("account"))
        return self.archive.search(
            str(arguments.get("query", "")),
            account=account,
            folder=arguments.get("folder"),
            since=arguments.get("since"),
            before=arguments.get("before"),
            limit=int(arguments.get("limit", 20)),
        )

    def _tool_get_message(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        mid = str(arguments.get("message_id", ""))
        return {**self.archive.get_message(mid), **self.location_snapshot().state(mid)}

    def _tool_get_thread(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.archive.get_thread(
            str(arguments.get("message_id", "")), limit=int(arguments.get("limit", 100))
        )

    def _tool_mailbox_stats(self, _arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.archive.stats()

    def _tool_list_attachments(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.archive.list_attachments(str(arguments.get("message_id", "")))

    def _tool_download_attachment(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        return self.archive.download_attachment(
            str(arguments.get("message_id", "")),
            str(arguments.get("attachment_id", "")),
            max_bytes=int(arguments.get("max_bytes", MAX_DOWNLOAD_BYTES)),
        )

    def _tool_stage_attachment(self, arguments: dict[str, Any], _principal: Principal) -> Any:
        if self.staged_attachments is None:
            raise RuntimeError("staged attachment storage is not configured")
        return self.staged_attachments.stage(
            filename=str(arguments["filename"]),
            mimetype=str(arguments["mimetype"]),
            content_base64=str(arguments["content_base64"]),
        )

    def _tool_get_draft_status(self, arguments: dict[str, Any], principal: Principal) -> Any:
        review = self.approvals.review(str(arguments.get("draft_id", "")))
        if review["created_client"] != principal.client_id:
            raise ValueError("draft belongs to a different client")
        return review

    def _tool_mail_operations_status(
        self, _arguments: dict[str, Any], _principal: Principal
    ) -> Any:
        return self.operations_status_provider()

    _READ_HANDLERS: ClassVar[dict[str, Callable[..., Any]]] = {
        "diagnose_message": _tool_diagnose_message,
        "submit_mail_feedback": _tool_submit_mail_feedback,
        "get_mail_feedback": _tool_get_mail_feedback,
        "list_mail_feedback": _tool_list_mail_feedback,
        "service_info": _tool_service_info,
        "health_status": _tool_health_status,
        "list_accounts": _tool_list_accounts,
        "list_folders": _tool_list_folders,
        "sync_status": _tool_sync_status,
        "sync_mail": _tool_sync_mail,
        "oauth_status": _tool_oauth_status,
        "find_verification_codes": _tool_find_verification_codes,
        "get_mail_preferences": _tool_get_mail_preferences,
        "edit_global_notes": _tool_edit_global_notes,
        "edit_mailbox_preferences": _tool_edit_mailbox_preferences,
        "list_recent": _tool_list_recent,
        "list_sent_metadata": _tool_list_sent_metadata,
        "count_mail": _tool_count_mail,
        "search_mail": _tool_search_mail,
        "get_message": _tool_get_message,
        "get_thread": _tool_get_thread,
        "mailbox_stats": _tool_mailbox_stats,
        "list_attachments": _tool_list_attachments,
        "download_attachment": _tool_download_attachment,
        "stage_attachment": _tool_stage_attachment,
        "get_draft_status": _tool_get_draft_status,
        "mail_operations_status": _tool_mail_operations_status,
    }

    def _payload_archive(self, arguments: dict[str, Any]) -> dict:
        return self._organization_payload(arguments, destination_kind="archive")

    def _payload_move_unrelated(self, arguments: dict[str, Any]) -> dict:
        return self._organization_payload(arguments, destination_kind="unrelated")

    def _payload_move(self, arguments: dict[str, Any]) -> dict:
        return self._organization_payload(arguments, destination_kind="move")

    def _payload_trash(self, arguments: dict[str, Any]) -> dict:
        return self._organization_payload(arguments, destination_kind="trash")

    _WRITE_PAYLOADS: ClassVar[dict[str, Callable[..., dict]]] = {}

    @staticmethod
    def _validate_argument_shape(name: str, arguments: dict[str, Any]) -> None:
        try:
            schema = TOOL_DEFINITIONS[name]["inputSchema"]
        except KeyError as exc:
            raise ValueError(f"unknown tool: {name}") from exc
        _validate_schema_value(arguments, schema, path="arguments")

    def _validate_account(self, account: object) -> str | None:
        if account is None or account == "" or account == "all":
            return None
        if not isinstance(account, str) or account not in self.accounts:
            raise ValueError("unknown or disabled account")
        return account

    @staticmethod
    def _addresses(value: object, *, required: bool) -> list[str]:
        if value is None and not required:
            return []
        if not isinstance(value, list) or len(value) > 50 or (required and not value):
            raise ValueError("recipient list is malformed")
        addresses: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str) or "\r" in item or "\n" in item:
                raise ValueError("recipient address is malformed")
            parsed = getaddresses([item])
            if not parsed:
                raise ValueError("recipient address is malformed")
            for _display, address in parsed:
                if not re.fullmatch(r"[^@\s]+@[^@\s]+", address) or len(address) > 320:
                    raise ValueError("recipient address is malformed")
                normalized = address.casefold()
                if normalized not in seen:
                    addresses.append(address)
                    seen.add(normalized)
        if len(addresses) > 50 or (required and not addresses):
            raise ValueError("recipient list is malformed")
        return addresses

    @staticmethod
    def _text(value: object, *, field: str, maximum: int, required: bool = True) -> str:
        if value is None and not required:
            return ""
        if not isinstance(value, str) or (required and not value.strip()) or len(value) > maximum:
            raise ValueError(f"{field} is malformed")
        if field == "subject" and ("\r" in value or "\n" in value):
            raise ValueError("subject contains a header injection")
        return value.strip() if field == "subject" else value

    def _attachment_refs(self, value: object) -> list[dict[str, str]]:
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > 20:
            raise ValueError("attachment references are malformed")
        result = []
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("attachment reference is malformed")
            if set(item) == {"message_id", "attachment_id"}:
                message_id = str(item["message_id"])
                attachment_id = str(item["attachment_id"])
                available = {
                    attachment["attachment_id"]: attachment
                    for attachment in self.archive.list_attachments(message_id)
                }
                if attachment_id not in available or not available[attachment_id]["available"]:
                    raise ValueError("attachment reference is unavailable")
                result.append({"message_id": message_id, "attachment_id": attachment_id})
            elif set(item) == {"staged_attachment_id"} and self.staged_attachments is not None:
                result.append(self.staged_attachments.describe(str(item["staged_attachment_id"])))
            else:
                raise ValueError("attachment reference is malformed")
        return result

    @staticmethod
    def _deduplicate_recipient_fields(
        to: list[str], cc: list[str], bcc: list[str]
    ) -> tuple[list[str], list[str], list[str]]:
        seen: set[str] = set()
        result: list[list[str]] = []
        for field in (to, cc, bcc):
            unique = []
            for address in field:
                normalized = address.casefold()
                if normalized not in seen:
                    unique.append(address)
                    seen.add(normalized)
            result.append(unique)
        return result[0], result[1], result[2]

    def _send_payload(self, arguments: dict[str, Any]) -> dict[str, Any]:
        account = self._validate_account(arguments.get("account"))
        if account is None:
            raise ValueError("a concrete sender account is required")
        sender = self._sender_address(account, arguments.get("from"))
        to, cc, bcc = self._deduplicate_recipient_fields(
            self._addresses(arguments.get("to"), required=True),
            self._addresses(arguments.get("cc"), required=False),
            self._addresses(arguments.get("bcc"), required=False),
        )
        return {
            "operation": "send",
            "account": account,
            "from": sender,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": self._text(arguments.get("subject"), field="subject", maximum=998),
            "body": self._text(arguments.get("body"), field="body", maximum=100000),
            "attachments": self._attachment_refs(arguments.get("attachments")),
            "date": self.now().astimezone(dt.UTC).isoformat(timespec="seconds"),
            "message_id": self._new_message_id(sender),
        }

    def _reply_payload(self, arguments: dict[str, Any]) -> dict[str, Any]:
        context = self.archive.message_context(str(arguments.get("message_id", "")))
        account = str(context["account"])
        sender = self.accounts[account].default_from_address
        subject = str(context["subject"] or "")
        if not subject.lower().startswith("re:"):
            subject = f"Re: {subject}"
        references = [*context["references_ids"]]
        original_message_id = str(context["message_id"] or "")
        if original_message_id:
            references.append(original_message_id)
        references = list(
            dict.fromkeys(
                normalized for item in references if (normalized := normalize_message_id(str(item)))
            )
        )
        reply_to = str(context.get("reply_to") or context["sender_email"])
        to = self._addresses([reply_to], required=True)
        cc = self._addresses(arguments.get("cc"), required=False)
        self_addresses = {
            address.casefold()
            for item in self.accounts.values()
            for address in item.allowed_from_addresses
        }
        if all(address.casefold() in self_addresses for address in to):
            original_to_value = str(context.get("recipients_to") or "")
            original_to = self._addresses(
                [original_to_value] if original_to_value else [], required=False
            )
            to = [item for item in original_to if item.casefold() not in self_addresses]
            if not to:
                raise ValueError("reply has no non-self recipient")
        if bool(arguments.get("reply_all", False)):
            originals = getaddresses(
                [str(context.get("recipients_to") or ""), str(context.get("recipients_cc") or "")]
            )
            existing = {item.casefold() for item in [*to, *cc, *self_addresses]}
            for _display, address in originals:
                normalized = address.strip().lower()
                if normalized and normalized.casefold() not in existing:
                    cc.append(normalized)
                    existing.add(normalized.casefold())
        to, cc, _bcc = self._deduplicate_recipient_fields(to, cc, [])
        quoted = "\n".join(f"> {line}" for line in str(context.get("body_text") or "").splitlines())
        outgoing = self._text(arguments.get("body"), field="body", maximum=100000)
        original_sender = (
            f"{context['sender_name']} <{context['sender_email']}>"
            if context.get("sender_name")
            else str(context["sender_email"])
        )
        body = f"{outgoing}\n\nOn {context['date_received']}, {original_sender} wrote:\n{quoted}\n"
        return {
            "operation": "reply",
            "account": account,
            "from": sender,
            "to": to,
            "cc": cc,
            "bcc": [],
            "subject": self._text(subject, field="subject", maximum=998),
            "body": self._text(body, field="body", maximum=100000),
            "in_reply_to": original_message_id,
            "references": references,
            "attachments": self._attachment_refs(arguments.get("attachments")),
            "date": self.now().astimezone(dt.UTC).isoformat(timespec="seconds"),
            "message_id": self._new_message_id(sender),
        }

    def _forward_payload(self, arguments: dict[str, Any]) -> dict[str, Any]:
        context = self.archive.message_context(str(arguments.get("message_id", "")))
        account = str(context["account"])
        sender = self.accounts[account].default_from_address
        subject = str(context["subject"] or "")
        if not subject.lower().startswith(("fw:", "fwd:")):
            subject = f"Fwd: {subject}"
        introduction = self._text(
            arguments.get("body"), field="body", maximum=100000, required=False
        )
        forwarded = (
            "---------- Forwarded message ----------\n"
            f"From: {context['sender_name']} <{context['sender_email']}>\n"
            f"Date: {context['date_received']}\n"
            f"Subject: {context['subject']}\n"
            f"To: {context['recipients_to']}\n\n"
            f"{context['body_text']}"
        )
        body = f"{introduction}\n\n{forwarded}" if introduction else forwarded
        to, cc, _bcc = self._deduplicate_recipient_fields(
            self._addresses(arguments.get("to"), required=True),
            self._addresses(arguments.get("cc"), required=False),
            [],
        )
        return {
            "operation": "forward",
            "account": account,
            "from": sender,
            "to": to,
            "cc": cc,
            "bcc": [],
            "subject": self._text(subject, field="subject", maximum=998),
            "body": self._text(body, field="body", maximum=100000),
            "forwarded_message_id": context["id"],
            "attachments": self._attachment_refs(arguments.get("attachments")),
            "date": self.now().astimezone(dt.UTC).isoformat(timespec="seconds"),
            "message_id": self._new_message_id(sender),
        }

    def _sender_address(self, account: str, requested: object) -> str:
        configured = self.accounts[account]
        allowed = {address.casefold(): address for address in configured.allowed_from_addresses}
        if requested is None or requested == "":
            return configured.default_from_address
        parsed = self._addresses([requested], required=True)
        if len(parsed) != 1:
            raise ValueError("From must contain exactly one address")
        try:
            return allowed[parsed[0].casefold()]
        except KeyError as exc:
            raise ValueError("From is not allowlisted for the configured account") from exc

    def _organization_payload(
        self, arguments: dict[str, Any], *, destination_kind: str
    ) -> dict[str, Any]:
        account = self._validate_account(arguments.get("account"))
        if account is None:
            raise ValueError("a concrete account is required")
        stable_id = str(arguments.get("stable_message_id", ""))
        context = self.archive.message_context(stable_id)
        if context["account"] != account:
            raise ValueError("message does not belong to the requested account")
        if destination_kind == "unrelated":
            destination = "Unrelated"
        elif destination_kind == "trash":
            destination = self.accounts[account].trash_folder
        elif destination_kind == "archive":
            destination = self.accounts[account].archive_folder
            requested = str(arguments.get("destination") or destination)
            if requested.casefold() != destination.casefold():
                raise ValueError("archive destination must match the account archive folder")
        else:
            requested = str(arguments.get("destination") or "")
            allowed = {
                folder.casefold(): folder for folder in self.accounts[account].safe_move_folders
            }
            try:
                destination = allowed[requested.casefold()]
            except KeyError as exc:
                raise ValueError("mail destination is not allowlisted for this account") from exc
        if destination_kind != "trash" and destination.casefold() not in {
            folder.casefold() for folder in self.accounts[account].safe_move_folders
        }:
            raise ValueError("mail destination is not allowlisted for this account")
        if not context["message_id"] and not context["raw_body_sha256"]:
            raise ValueError("message lacks enough immutable provider identity to move safely")
        source = self._provider_location(
            context,
            account=account,
            requested=arguments.get("source_folder"),
            excluded_folder=destination,
        )
        self._check_organization_capabilities(account, destination_kind)
        return {
            "operation": destination_kind,
            "account": account,
            "stable_message_id": stable_id,
            "source_folder": source["folder"],
            "source_uid": source["uid"],
            "source_uid_validity": source["uid_validity"],
            "provider_message_id": str(context["message_id"] or ""),
            "raw_body_sha256": str(
                source.get("raw_body_sha256") or context["raw_body_sha256"] or ""
            ),
            "destination": destination,
            "copy_preserve_source_fallback": (
                False
                if destination_kind == "trash"
                else self.accounts[account].copy_preserve_source_fallback
            ),
            **({"uidplus_move_fallback": True} if account in self.uidplus_move_accounts else {}),
            **(
                {
                    "subject": str(context.get("subject") or ""),
                    "sender": str(context.get("sender_email") or ""),
                    "date_received": str(context.get("date_received") or ""),
                }
                if destination_kind == "trash"
                else {}
            ),
        }

    def _check_organization_capabilities(self, account: str, operation: str) -> None:
        if self.organization_capabilities_provider is None:
            return
        # A batch needs one authenticated read per account, not one per message.
        # Execution still verifies capabilities on its own provider connection.
        # Only the per-account lock is held across the provider call.
        with self._organization_capabilities_lock:
            account_lock = self._organization_capabilities_locks.setdefault(
                account, threading.Lock()
            )
        with account_lock:
            cached = self._organization_capabilities_cache.get(account)
            now = self.now()
            if cached is not None and cached[0] > now:
                capabilities = cached[1]
                if capabilities is None:
                    raise ProviderNotAttempted(
                        "provider capabilities were unavailable less than a minute ago; retry later"
                    )
            else:
                try:
                    capabilities = dict(self.organization_capabilities_provider(account))
                    if not isinstance(capabilities.get("native_move"), bool):
                        raise ValueError("provider MOVE capability could not be verified")
                except Exception:
                    self._organization_capabilities_cache[account] = (
                        now + dt.timedelta(seconds=60),
                        None,
                    )
                    raise
                self._organization_capabilities_cache[account] = (
                    now + dt.timedelta(minutes=5),
                    capabilities,
                )
        if capabilities["native_move"]:
            return
        if account in self.uidplus_move_accounts and capabilities.get("uidplus") is True:
            return
        if operation != "trash" and self.accounts[account].copy_preserve_source_fallback:
            return
        raise ValueError(
            f"PROVIDER_NATIVE_MOVE_UNAVAILABLE: {account} supports neither native IMAP MOVE "
            "nor an enabled UIDPLUS move, so this service cannot move its mail to the trash "
            "or out of the source folder."
        )

    def _mark_payload(self, arguments: dict[str, Any]) -> dict[str, Any]:
        account = self._validate_account(arguments.get("account"))
        if account is None:
            raise ValueError("a concrete account is required")
        stable_id = str(arguments.get("stable_message_id", ""))
        context = self.archive.message_context(stable_id)
        if context["account"] != account:
            raise ValueError("message does not belong to the requested account")
        action = str(arguments.get("action") or "")
        if action not in _MARK_ACTIONS:
            raise ValueError("mail mark action is not allowlisted")
        if not context["message_id"] and not context["raw_body_sha256"]:
            raise ValueError("message lacks enough immutable provider identity to mark safely")
        source = self._provider_location(
            context,
            account=account,
            requested=arguments.get("source_folder"),
        )
        return {
            "operation": "mark",
            "account": account,
            "stable_message_id": stable_id,
            "source_folder": source["folder"],
            "source_uid": source["uid"],
            "source_uid_validity": source["uid_validity"],
            "provider_message_id": str(context["message_id"] or ""),
            "raw_body_sha256": str(
                source.get("raw_body_sha256") or context["raw_body_sha256"] or ""
            ),
            "action": action,
        }

    def _provider_location(
        self,
        context: dict[str, Any],
        *,
        account: str,
        requested: object = None,
        excluded_folder: str | None = None,
    ) -> dict[str, Any]:
        locations: list[dict[str, Any]] = []
        raw_locations = context.get("locations")
        if isinstance(raw_locations, list):
            for item in raw_locations:
                if not isinstance(item, dict) or str(item.get("account")) != account:
                    continue
                folder = str(item.get("folder") or "")
                try:
                    uid = int(item.get("uid") or 0)
                except (TypeError, ValueError):
                    continue
                if folder and uid > 0:
                    locations.append({**item, "folder": folder, "uid": uid})
        if not isinstance(raw_locations, list) and str(context.get("account")) == account:
            folder = str(context.get("folder") or "")
            uid = int(context.get("uid") or 0)
            if folder and uid > 0:
                locations.append(
                    {
                        "account": account,
                        "folder": folder,
                        "uid": uid,
                        "uid_validity": "",
                        "raw_body_sha256": str(context.get("raw_body_sha256") or ""),
                    }
                )
        requested_folder = str(requested or "")
        excluded = str(excluded_folder or "").casefold()
        if requested_folder:
            candidates = [
                item
                for item in locations
                if item["folder"].casefold() == requested_folder.casefold()
            ]
            if not candidates:
                raise ValueError("requested source folder has no current provider location")
        else:
            candidates = list(locations)
            preferred = [str(context.get("folder") or ""), *self.accounts[account].folders]
            rank = {folder.casefold(): index for index, folder in enumerate(preferred) if folder}
            candidates.sort(
                key=lambda item: (rank.get(item["folder"].casefold(), len(rank)), item["folder"])
            )
        if excluded:
            candidates = [item for item in candidates if item["folder"].casefold() != excluded]
        if not candidates:
            if excluded and any(item["folder"].casefold() == excluded for item in locations):
                raise ValueError("message is already in the requested destination")
            raise ValueError("message has no current provider location for this action")
        selected = dict(candidates[0])
        selected["uid_validity"] = str(selected.get("uid_validity") or "") or self._uid_validity(
            account, selected["folder"]
        )
        return selected

    def _uid_validity(self, account: str, folder: str) -> str:
        matches = [
            item
            for item in self.archive.sync_status()
            if item["account"] == account and item["folder"] == folder
        ]
        if len(matches) != 1 or not matches[0].get("uid_validity"):
            raise ValueError("message folder lacks a current UIDVALIDITY sync watermark")
        return str(matches[0]["uid_validity"])

    @staticmethod
    def _new_message_id(sender: str) -> str:
        domain = sender.rsplit("@", 1)[-1].casefold()
        return f"<{uuid.uuid4().hex}@evergarden.{domain}>"

    def _draft_result(self, draft) -> dict:
        approval = (
            self.approvals.approval_for(draft.draft_id)
            if draft.kind in self.approvals.auto_approve_kinds
            else None
        )
        result = {
            "draft_id": draft.draft_id,
            "kind": draft.kind.value,
            "payload_hash": draft.payload_hash,
            "expires_at": draft.expires_at.astimezone(dt.UTC).isoformat(timespec="seconds"),
            "review_packet": copy.deepcopy(draft.payload),
            "requires_human_approval": approval is None,
            "approval_path": (
                f"/review?batch=trash&draft_id={draft.draft_id}"
                if draft.kind is IntentKind.TRASH
                else f"/review/send?draft_id={draft.draft_id}"
                if draft.kind is IntentKind.SEND
                else f"/review?mode=single&draft_id={draft.draft_id}"
            ),
            "approval_available_via_mcp": approval is not None,
            "execution_owner": (
                "server"
                if approval is None and draft.kind in self.approval_dispatch_kinds
                else "client"
            ),
        }
        if approval is not None:
            result["approval_id"] = approval.approval_id
            result["approval_expires_at"] = (
                approval.expires_at.astimezone(dt.UTC).isoformat(timespec="seconds")
                if approval.expires_at is not None
                else None
            )
        return result


# Every write-preparing tool and the approval kind its draft carries. The
# write guard applies to exactly this table; test_tool_registry asserts the
# table plus the read handlers cover every defined tool.
WRITE_PREPARE_KINDS: dict[str, IntentKind] = {
    "prepare_send": IntentKind.SEND,
    "prepare_reply": IntentKind.SEND,
    "prepare_forward": IntentKind.SEND,
    "preview_archive": IntentKind.ARCHIVE,
    "preview_move_unrelated": IntentKind.MOVE,
    "preview_move": IntentKind.MOVE,
    "preview_mark": IntentKind.MARK,
    "preview_trash": IntentKind.TRASH,
}

APPROVED_EXECUTION_KINDS: dict[str, IntentKind] = {
    "send_approved": IntentKind.SEND,
    "archive_approved": IntentKind.ARCHIVE,
    "move_unrelated_approved": IntentKind.MOVE,
    "move_approved": IntentKind.MOVE,
    "mark_approved": IntentKind.MARK,
    "trash_approved": IntentKind.TRASH,
}

ToolRuntime._WRITE_PAYLOADS.update(
    {
        "prepare_send": ToolRuntime._send_payload,
        "prepare_reply": ToolRuntime._reply_payload,
        "prepare_forward": ToolRuntime._forward_payload,
        "preview_archive": ToolRuntime._payload_archive,
        "preview_move_unrelated": ToolRuntime._payload_move_unrelated,
        "preview_move": ToolRuntime._payload_move,
        "preview_mark": ToolRuntime._mark_payload,
        "preview_trash": ToolRuntime._payload_trash,
    }
)
