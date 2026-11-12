# Advanced: OAuth for MCP clients (Authelia example)

API keys are the simple way to connect an agent. If you prefer that MCP clients
sign in through a standard OAuth login with short-lived access tokens, run an
OAuth 2.0 / OpenID Connect authorization server and let Evergarden verify its
tokens. This page uses [Authelia](https://www.authelia.com/) as the example;
any server that issues JWT access tokens with an audience claim, or supports
token introspection, can work.

This is independent of the web UI login and of mailbox OAuth: an MCP access
token never opens a browser session, and the browser cookie is never accepted
at `/mcp`. API keys keep working alongside OAuth.

## What Evergarden checks

For every bearer token Evergarden verifies the signature (JWT via the issuer's
JWKS) or asks the introspection endpoint, then requires:

- the audience to contain `EVERGARDEN_MCP_RESOURCE` (for example
  `https://mail.example.com/mcp`),
- an unexpired token,
- the `mail:*` scopes each tool needs (see [mcp.md](../mcp.md#scopes-and-tools)).

Unauthenticated requests get HTTP 401 with a pointer to
`<origin>/.well-known/oauth-protected-resource/mcp`, which names the
authorization server so clients can discover it.

## Evergarden settings

In `.local/run/runtime.env` (an HTTPS public origin is required):

```dotenv
EVERGARDEN_OAUTH_ISSUER=https://auth.example.com
# Either JWT verification:
EVERGARDEN_OAUTH_JWKS_URL=https://auth.example.com/jwks.json
# or introspection (all three together):
#EVERGARDEN_OAUTH_INTROSPECTION_URL=https://auth.example.com/api/oidc/introspection
#EVERGARDEN_OAUTH_INTROSPECTION_CLIENT_ID=evergarden-mcp
#EVERGARDEN_OAUTH_INTROSPECTION_CLIENT_SECRET_FILE=/run/secrets/oauth_introspection_secret
```

Use the JWKS URL your server publishes in its discovery document; do not guess
it. For introspection, the secret file must be mounted into the `mcp` service
with a Compose override file of your own. Run `docker compose up -d` after the
change.

Without a JWKS URL or introspection, OAuth is off: no OAuth token is accepted,
the protected-resource metadata lists no `authorization_servers`,
`WWW-Authenticate` carries no `resource_metadata`, and the web UI hides its
OAuth guide. MCP clients then use API keys only.

With a JWKS URL, keys are fetched in a worker thread (off the event loop) when
a request needs a key that is not cached, so the first OAuth request after a
start waits for that fetch. Fetches use a 5-second
timeout, no redirects and a 512 KiB limit, and reused for up to 5 minutes. A
token whose key id is not cached triggers at most one fetch per 60 seconds, so
a newly rotated signing key can be rejected for up to a minute. Cached keys
keep working while the JWKS endpoint is down; if it is down when `mcp` starts,
OAuth tokens are rejected until a fetch succeeds (API keys are unaffected).
Tokens without a `kid` header are rejected.

## Authelia clients

`deploy/scripts/configure_authelia_mcp.py` adds two public clients to an
existing Authelia configuration, one for Codex and one for Claude Code
(authorization code with PKCE S256, the `mail:*` scopes, your MCP resource as
audience, two-factor policy), and sets a refresh-token lifespan for them. It
never prints the configuration or keys, and writes a separate mode-0600
candidate file:

```bash
uv run python deploy/scripts/configure_authelia_mcp.py \
  --config /path/to/authelia/configuration.yml \
  --output /path/to/authelia/configuration.candidate.yml \
  --resource https://mail.example.com/mcp \
  --codex-redirect-uri http://127.0.0.1:32124/callback/<codex-callback-id> \
  --claude-redirect-uri http://localhost:32125/callback \
  --refresh-token-lifespan 30d
```

Client ids default to `codex-evergarden` and `claude-code-evergarden`
(`--codex-client-id`, `--claude-client-id`). Validate the candidate with your
Authelia version before replacing the active file. `--rotate-signing-key
--signing-key-id <kid>` replaces the RS256 signing key in the candidate.

## Client side

The **OAuth (optional)** tab of **Connect an MCP agent** shows ready snippets
with your URL and scopes. For Claude Code:

```bash
claude mcp add-json evergarden-mail \
  '{"type":"http","url":"https://mail.example.com/mcp","oauth":{"clientId":"claude-code-evergarden","callbackPort":32125,"scopes":"openid offline_access mail:metadata mail:read ..."}}' \
  --scope user
claude mcp login evergarden-mail
```

For Codex (`~/.codex/config.toml`), then `codex mcp login evergarden-mail`:

```toml
mcp_oauth_callback_port = 32124
mcp_oauth_credentials_store = "keyring"

[mcp_servers.evergarden-mail]
url = "https://mail.example.com/mcp"
auth = "oauth"
oauth_resource = "https://mail.example.com/mcp"
scopes = ["openid", "offline_access", "mail:metadata", "mail:read"]

[mcp_servers.evergarden-mail.oauth]
client_id = "codex-evergarden"
```

Remove any static `Authorization` header or `bearer_token_env_var` before
switching a client to OAuth; a rejected bearer token does not fall back to
OAuth.

Check discovery without credentials:

```bash
curl -fsS https://mail.example.com/.well-known/oauth-protected-resource/mcp
curl -fsS https://auth.example.com/.well-known/oauth-authorization-server
```
