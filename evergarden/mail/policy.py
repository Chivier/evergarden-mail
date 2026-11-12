"""Single source of truth for what each mail account may do.

Every service that needs account semantics (readable, writable,
receive-only, UIDPLUS move) must take its values from one
``AccountPolicy`` instead of re-deriving them from settings or account
lists.  Ad-hoc derivations in wiring code are how a bridge account once
lost its receive-only restriction when native sync was enabled.
"""

from __future__ import annotations

import dataclasses

from evergarden.config import Settings
from evergarden.mail.models import AccountConfig, load_account_configs


@dataclasses.dataclass(frozen=True)
class AccountPolicy:
    """What each alias may do.

    - ``accounts``: natively enabled accounts; the only candidates for
      provider writes and background sync.
    - ``read_accounts``: ``accounts`` plus Thunderbird-bridge-only
      mailboxes; everything that may be read or listed.
    - ``receive_only_accounts``: aliases that must never reach a provider
      write, no matter how the request arrives.  A bridge account stays
      here even after native sync is enabled for it.
    - ``uidplus_move_accounts``: enabled aliases allowed the UIDPLUS move
      strategy.
    """

    accounts: tuple[AccountConfig, ...]
    read_accounts: tuple[AccountConfig, ...]
    receive_only_accounts: frozenset[str]
    uidplus_move_accounts: frozenset[str]

    @classmethod
    def build(cls, settings: Settings, accounts: tuple[AccountConfig, ...]) -> AccountPolicy:
        bridge = settings.thunderbird_bridge_account_set
        enabled = {account.alias for account in accounts}
        bridge_extras = tuple(
            account
            for account in load_account_configs(settings.account_config_file, include_disabled=True)
            if account.alias in bridge and account.alias not in enabled
        )
        read_accounts = (*accounts, *bridge_extras)
        return cls(
            accounts=accounts,
            read_accounts=read_accounts,
            receive_only_accounts=bridge & frozenset(account.alias for account in read_accounts),
            uidplus_move_accounts=settings.uidplus_move_account_set & frozenset(enabled),
        )
