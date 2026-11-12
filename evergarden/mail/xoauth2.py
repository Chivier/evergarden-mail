from __future__ import annotations

from collections.abc import Callable


def xoauth2_response(address: str, token: str, *, as_bytes: bool = True) -> Callable:
    """Send credentials once; finish a provider's error challenge with an empty response."""
    blob = f"user={address}\x01auth=Bearer {token}\x01\x01"
    response = blob.encode() if as_bytes else blob
    empty = b"" if as_bytes else ""
    sent = False

    def respond(_challenge=None):
        nonlocal sent
        if sent:
            return empty
        sent = True
        return response

    return respond
