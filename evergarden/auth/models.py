from __future__ import annotations

import dataclasses
from collections.abc import Iterable


@dataclasses.dataclass(frozen=True)
class Principal:
    subject: str
    client_id: str
    scopes: frozenset[str]
    audience: frozenset[str]
    issuer: str

    @classmethod
    def build(
        cls,
        *,
        subject: str,
        client_id: str,
        scopes: str | Iterable[str],
        audience: str | Iterable[str],
        issuer: str,
    ) -> Principal:
        scope_set = frozenset(scopes.split() if isinstance(scopes, str) else scopes)
        audience_set = frozenset([audience] if isinstance(audience, str) else audience)
        return cls(subject, client_id, scope_set, audience_set, issuer)


class AuthorizationError(RuntimeError):
    status_code = 401
    oauth_error = "invalid_token"


class AuthenticationRequired(AuthorizationError):
    oauth_error = "invalid_token"


class InvalidToken(AuthorizationError):
    oauth_error = "invalid_token"


class InsufficientScope(AuthorizationError):
    status_code = 403
    oauth_error = "insufficient_scope"

    def __init__(self, required: str):
        super().__init__(f"required scope is missing: {required}")
        self.required = required
