from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

# A single-machine install serves MCP and its metadata over plain HTTP on a
# loopback port; every other host must use HTTPS.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _secure_scheme(parts) -> bool:
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS)


def protected_resource_metadata_url(resource: str) -> str:
    """Construct the RFC 9728 well-known URL, including a resource path."""
    parts = urlsplit(resource)
    if not _secure_scheme(parts) or not parts.netloc or parts.fragment:
        raise ValueError(
            "protected resource identifier must be an HTTPS (or loopback HTTP) URI "
            "without a fragment"
        )
    suffix = parts.path.rstrip("/")
    path = f"/.well-known/oauth-protected-resource{suffix}"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def authorization_server_metadata_url(issuer: str) -> str:
    """Construct the RFC 8414 metadata URL for an issuer identifier.

    RFC 8414 inserts the well-known component before a non-empty issuer path.
    For example, ``https://id.example/tenant`` becomes
    ``https://id.example/.well-known/oauth-authorization-server/tenant``.
    """
    parts = urlsplit(issuer)
    if (
        not _secure_scheme(parts)
        or not parts.netloc
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise ValueError(
            "authorization server issuer must be an HTTPS (or loopback HTTP) URI without "
            "credentials, query, or fragment"
        )
    issuer_path = parts.path.rstrip("/")
    path = f"/.well-known/oauth-authorization-server{issuer_path}"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def protected_resource_metadata(*, resource: str, issuer: str | None, scopes: list[str]) -> dict:
    """RFC 9728 metadata; ``issuer`` is None when no authorization server is trusted.

    ``authorization_servers`` is optional in RFC 9728. Leaving it out tells MCP
    clients there is no OAuth flow to start, so they use their static bearer.
    """
    protected_resource_metadata_url(resource)
    metadata: dict = {"resource": resource}
    if issuer is not None:
        authorization_server_metadata_url(issuer.rstrip("/"))
        metadata["authorization_servers"] = [issuer.rstrip("/")]
    metadata["scopes_supported"] = sorted(set(scopes))
    metadata["bearer_methods_supported"] = ["header"]
    return metadata
