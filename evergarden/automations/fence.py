from __future__ import annotations

import dataclasses
import enum


class SideEffect(enum.StrEnum):
    SMTP_SEND = "smtp_send"
    IMAP_MOVE = "imap_move"
    IMAP_FLAG = "imap_flag"
    IMAP_TRASH_MOVE = "imap_trash_move"
    PROVIDER_TOKEN_REFRESH = "provider_token_refresh"  # noqa: S105 - effect name


FORBIDDEN_EFFECT_NAMES = frozenset({"delete", "trash", "expunge", "imap_delete"})


class FenceRejected(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(f"side effect fence rejected: {reason}")
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class FenceConfig:
    """Writer identity of this process; see ``evergarden.config.Settings``."""

    host_id: str
    active_writer: str
    writer_epoch: int
    side_effects_enabled: bool
    trash_actions_enabled: bool = False


@dataclasses.dataclass(frozen=True)
class LeaseToken:
    job_id: str
    scheduled_slot: str
    owner_host: str
    writer_epoch: int
    nonce: str


class SideEffectFence:
    def __init__(self, config: FenceConfig):
        self.config = config

    def assert_allowed(self, effect: SideEffect | str, lease: LeaseToken | None) -> None:
        name = effect.value if isinstance(effect, SideEffect) else str(effect)
        if name in FORBIDDEN_EFFECT_NAMES:
            raise FenceRejected("delete/trash/expunge is permanently forbidden")
        if not self.config.side_effects_enabled:
            raise FenceRejected("external side effects are disabled")
        if name == SideEffect.IMAP_TRASH_MOVE.value and not self.config.trash_actions_enabled:
            raise FenceRejected("reversible Trash actions are disabled")
        if self.config.active_writer != self.config.host_id:
            raise FenceRejected("this host is not the active writer")
        if lease is None:
            raise FenceRejected("a writer lease is required")
        if lease.owner_host != self.config.host_id:
            raise FenceRejected("lease belongs to another host")
        if lease.writer_epoch != self.config.writer_epoch:
            raise FenceRejected("lease writer epoch is stale")

    def probe(
        self, effect: SideEffect | str, lease: LeaseToken | None = None
    ) -> dict[str, str | bool]:
        try:
            self.assert_allowed(effect, lease)
        except FenceRejected as exc:
            return {"allowed": False, "reason": exc.reason}
        return {"allowed": True, "reason": "all writer checks passed"}
