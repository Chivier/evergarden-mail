# Security

Evergarden gives AI agents access to your mail. This page describes what it
protects, how, and where the protection ends. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## What is protected

- **Your mailboxes.** An agent can read and draft, but cannot send, move, mark
  or trash mail without an approval, and cannot approve anything itself.
- **Your credentials.** Mailbox passwords, OAuth tokens and keys never reach an
  agent, the browser or the logs.
- **Your mail and notes.** They stay on your host, in files only your user can
  read, and are never committed to Git.

## Threats and controls

| Threat | Control |
|---|---|
| An agent (or a prompt injection in a mail) sends, moves or deletes mail | No tool writes directly. Writes are drafts that need an approval, which only the signed-in human can give (or `EVERGARDEN_AUTO_APPROVE`, never for Trash). Mail and notes are treated as data and cannot change scopes, allowlists or approvals. |
| An approved action hits the wrong message | The draft pins account, folder, UID, UIDVALIDITY, Message-ID and content hash; all are checked again at the provider right before the change. Moves only go to allowlisted folders of the same mailbox. |
| A change after approval | The approval is bound to the draft's SHA-256 payload hash; any difference is rejected. |
| Duplicate sends or moves | One approval per draft, an atomic claim before execution, a fixed Message-ID, a Sent-folder check before and after sending, and read-only verification of unknown outcomes. Sends are never replayed. |
| Data loss | No permanent delete, no plain `EXPUNGE`, no emptying Trash. Trash is a move to one configured folder and needs its own switch and scope. Disabling a mailbox keeps its data. |
| Bcc disclosure | Bcc only in the SMTP envelope, never in headers or normal logs. |
| A stolen MCP token | Scope-limited, expiring, revocable at once. It can read what its scopes allow and prepare drafts, but cannot approve. |
| Forged browser identity | Own administrator login (scrypt), signed HttpOnly SameSite=Strict cookie (`__Host-` prefixed when Secure), CSRF token on every change, server-side sign-out, login throttling per client address. The gateway clears caller-supplied `Remote-*` identity headers and decides the client address itself (see [Browser sessions and sign-in](#browser-sessions-and-sign-in)). `/mcp` ignores the cookie. |
| OAuth code or token theft | PKCE S256, encrypted one-time state that expires after ten minutes, exact redirect URI, fixed provider endpoints, tokens only in the encrypted store. |
| Active content in mail | Mail is shown as sanitized plain text; HTML is never rendered and no remote content is fetched. The web pages load no external scripts, fonts or trackers, under a strict Content-Security-Policy. |
| Dangerous attachments | Separate scope, size, type, content and macro checks; never opened by Evergarden. |
| Verification-code abuse | Codes are redacted everywhere except the dedicated, recent, context-bound lookup, and are never submitted automatically. |
| Secrets in the repository | Runtime state lives under the ignored `.local/`; a privacy scanner and gitleaks run in pre-commit and CI. |

## Containers

All application containers run as your host user (`EVERGARDEN_UID`), with a
read-only root filesystem, every Linux capability dropped, `no-new-privileges`
and a size-limited `/tmp`. Only the gateway and the direct MCP and approval
ports are published, all on `127.0.0.1`. This table follows
`docker-compose.yaml`; host paths are relative to the deployment root.

| Service | Networks | Mounts | Published |
|---|---|---|---|
| `gateway` | internal, egress | `deploy/nginx/evergarden-gateway.conf` (ro), `deploy/nginx/real-ip/` (ro). No data, no secrets. | `127.0.0.1:8788` |
| `mail-ui` | internal only | `.local/data/archive` (rw, for the Thunderbird bridge), `credential_store_key` (ro), `mail_ui_mcp_token` (ro), `admin_credentials.json` (ro), `admin_session_key` (ro), `.local/run/mail-config` (rw, mailbox admin), `.local/run/mcp-api-keys` (rw, API keys) | none |
| `approval-ui` | internal, egress, db | `.local/data/archive` (rw mount, opened read-only to show the message under review), `.local/data/secrets` (rw, OAuth tokens), `credential_store_key` (ro), `mail-config` (ro), `pgpass` (ro), `admin_session_key` (ro) | `127.0.0.1:8421` |
| `mcp` | internal, egress, db | `.local/data/archive` (rw), `.local/data/secrets` (rw), `compatibility_tokens.json` (ro), `mcp-api-keys` (ro), `credential_store_key` (ro), `mail-config` (ro), `pgpass` (ro) | `127.0.0.1:8420` |
| `scheduler`, `worker` | internal, egress, db | `.local/data/archive` (rw), `.local/data/recovery` (ro), `.local/data/reports` (rw), `.local/data/secrets` (rw), `credential_store_key` (ro), `mail-config` (ro), `pgpass` (ro) | none |
| `migrate` | db only | `pgpass` (ro) | none |
| `postgres` | db only | volume `<project>-postgres`, `postgres_password` (ro) | none |
| `oauth-maintenance` (optional) | internal, egress | `.local/data/archive` (rw), `.local/data/secrets` (rw), `credential_store_key` (ro), `mail-config` (ro) | none |
| `mfa-autologin` (optional) | egress only | `.local/data/secrets` (rw), `.local/data/reports` (rw), `credential_store_key` (ro), `mail-config` (ro) | none |

The `internal` and `db` networks have no route to the internet. `postgres` is
only on `db`, together with the services that hold database credentials
(`migrate`, `mcp`, `approval-ui`, `worker`, `scheduler`). The `mail-ui`
container, which serves the browser, cannot reach the internet or `postgres`
and holds no database credentials (no `pgpass` or `postgres_password` is
mounted). It reaches mail only through MCP with its own token. The gateway,
`oauth-maintenance` and `mfa-autologin` cannot reach `postgres` either. The administrator password hash is
mounted only in `mail-ui`. `postgres` runs with `no-new-privileges` but keeps its
image's default user handling. The gateway keeps the four capabilities nginx
needs to start (`CHOWN`, `DAC_OVERRIDE`, `SETGID`, `SETUID`).

## Secrets

| Secret | File | Created by | Notes |
|---|---|---|---|
| Credential store key | `.local/run/credential_store_key` | setup | Decrypts every stored mailbox credential, together with `EVERGARDEN_HOST_ID`. Back it up; setup refuses to create a new key when a credential store already exists. |
| Postgres password | `.local/run/postgres_password`, `pgpass` | setup | The only 0640 file, so the Postgres container can read it through your group. |
| Administrator password | `.local/run/admin_credentials.json` | setup | scrypt hash only. The password is printed once. |
| Session key | `.local/run/admin_session_key` | setup | Signs browser sessions. Replacing it signs every browser out. |
| Sign-out record | `.local/run/mail-config/admin_session_revocations.json` | web UI (on sign-out) | Not a secret, but integrity matters: per-administrator "signed out before" times, mode 0600. See below. |
| Web UI's MCP token | `.local/run/mail_ui_mcp_token`, `compatibility_tokens.json` | setup | Valid 365 days; renew with `./deploy/setup --renew-mail-ui-grant`. The registry holds only its hash. |
| API keys | `.local/run/mcp-api-keys/api_keys.json` | web UI | Hashes only; at most 32 keys of at most 365 days. |
| Mailbox passwords, OAuth tokens, Google client | `.local/data/secrets/credentials.db` | `set-password`, OAuth pages, `set-google-client` | AES-256-GCM; each record bound to host id, record id and version. |

Directories under `.local/` are mode 0700 and files 0600. Passwords enter only
through a no-echo prompt or standard input, never through command arguments or
environment variables. If a token or password may have leaked into a chat, log
or commit, revoke it at its source (API key in the web UI, app password or
OAuth grant at the provider); encryption at rest does not make a leaked token
safe.

For keeping deployment secrets in Git encrypted with SOPS and age, see
[advanced/sops.md](advanced/sops.md).

## Browser sessions and sign-in

- **Sessions.** A successful sign-in sets a signed, HttpOnly, SameSite=Strict
  cookie valid for `EVERGARDEN_ADMIN_SESSION_TTL_SECONDS`: 7 days by default,
  at most 30 days (`2592000`). With Secure cookies on (any `https://` origin)
  the cookie is named `__Host-evergarden_admin_session`, which browsers only
  accept from a secure origin with `Path=/` and no `Domain`; on a loopback
  `http://` install it is `evergarden_admin_session`. Your reverse proxy or CDN
  must not rewrite cookie names, domains or paths.
- **Sign-out is server-side and global.** Signing out records the current time
  for that administrator in `EVERGARDEN_ADMIN_SESSION_REVOCATION_FILE`
  (default `/run/mail-config/admin_session_revocations.json`, which is
  `.local/run/mail-config/admin_session_revocations.json` on the host). Both
  the web UI and the approval pages reject every cookie of that administrator
  issued at or before that time, so sign-out ends the session on **all**
  browsers and devices, including a copied cookie. The web UI writes the file
  atomically with mode 0600; the approval pages only read it (they must see
  the same `mail-config` directory). A missing file means nobody has signed
  out yet. If the sign-out cannot be recorded, the browser's cookie is still
  deleted and the server answers HTTP 503 with `LOGOUT_NOT_RECORDED`; other
  sessions then stay valid.
- **A damaged sign-out record fails closed.** If the file has any group or
  other permission bits (anything but 0600), is a symlink, larger than 64 KiB or not the expected JSON,
  every session is rejected (HTTP 401) and sign-in answers HTTP 503. To
  recover, delete the file: access returns at once, without a restart. Deleting
  it also forgets earlier sign-outs, so a cookie you meant to end becomes valid
  again until it expires; rotate the session key as well if that matters
  (`manage_admin_credentials.py --rotate-session-key`, see
  [operations.md](operations.md#reset-the-administrator-password)).
- **Sign-in throttle.** The web UI counts failed sign-ins per client address:
  15 within 15 minutes by default (`EVERGARDEN_ADMIN_LOGIN_MAX_FAILURES`,
  `EVERGARDEN_ADMIN_LOGIN_WINDOW_SECONDS`; the SOPS path writes 5, see
  [configuration.md](configuration.md#sign-in-and-session-defaults)). Then it
  answers HTTP 429 with `Retry-After` until the window passes. The client
  address is the single `X-Forwarded-For` value the gateway sends, which it
  derives according to `EVERGARDEN_GATEWAY_REAL_IP`
  ([configuration.md](configuration.md#real-client-address)); forwarding
  headers a client adds itself do not change it. IPv6 clients are counted per
  /64 network, because one host usually controls a whole /64 and can pick any
  source address in it; IPv4-mapped IPv6 addresses count as their IPv4
  address. The counters live in memory, are bounded to 4096 buckets and reset
  when `mail-ui` restarts.
- **Password checks off the event loop.** The scrypt check runs in a worker
  thread, at most two at a time. A sign-in that cannot get a slot within half a
  second gets HTTP 429 with `Retry-After: 1` and does not count as a failure,
  so a flood of sign-in attempts cannot stall the workbench.
- **MCP OAuth discovery.** The MCP endpoint advertises an authorization server
  only when it can verify that server's tokens (`EVERGARDEN_OAUTH_JWKS_URL` or
  introspection configured). JWKS keys are fetched in a worker thread (off the
  event loop) when a request needs a key that is not cached, with a short
  timeout, and then cached; an unknown key id triggers at most one fetch per
  minute. See [advanced/authelia-oauth.md](advanced/authelia-oauth.md).

## Trade-offs and known limits

- **Auto-approval.** `EVERGARDEN_AUTO_APPROVE` removes the human click for the
  listed kinds. Every other check still applies (payload hash, one-time claim,
  allowlists, writer fence), and Trash is never auto-approvable. But a token
  with a write scope can then send, archive, move or mark mail without a human
  while the policy is on. Leave it empty unless you accept that.
- **Optional MFA auto-login** stores the Microsoft password and the TOTP seed of
  the account in the encrypted credential store, so that a headless browser can
  answer sign-in prompts unattended. This collapses two factors into one:
  whoever holds the credential store and its key can sign in as the account.
  It is off by default and may violate your organisation's sign-in policy. See
  [advanced/mfa-autologin.md](advanced/mfa-autologin.md).
- **Client address and the sign-in throttle.** In the default `direct` gateway
  mode the client is whoever connects to the gateway. Behind a reverse proxy
  that is the proxy, so all remote clients share one throttle bucket and
  someone who knows your URL can lock you out for the window by guessing
  wrong. Set `EVERGARDEN_GATEWAY_REAL_IP=proxy` (or `cloudflare`) so each
  client gets its own bucket. Those modes trust `X-Forwarded-For` (and, from
  Cloudflare's addresses, `CF-Connecting-IP`) from the trusted proxy ranges, so
  anything else that can reach the gateway port from those ranges, including
  other users of the host through the loopback port, can pick any address and
  dodge the throttle. The same holds for clients from a private range (LAN,
  VPN) when the proxy appends to `X-Forwarded-For` instead of replacing it.
  Keep the gateway reachable only by the proxy, have the proxy replace the
  header, and narrow `EVERGARDEN_GATEWAY_TRUSTED_PROXIES`. Buckets are per
  address, or per /64 for IPv6; there is no global ceiling, so an attacker with
  many IPv4 addresses or many /64 networks gets 15 guesses for each (and at
  most two password checks run at a time). Use a strong password. The password
  itself is not weakened either way.
- **Sessions are bearer cookies.** Until you sign out or it expires, whoever
  holds a copy of the session cookie is signed in. Sign-out ends every session
  of that administrator at once; rotating the session key ends everyone's.
- **API keys vs OAuth.** API keys are simple and revocable at once, but whoever
  holds the administrator session can create one. An external OAuth server
  ([advanced/authelia-oauth.md](advanced/authelia-oauth.md)) adds its own login
  and short-lived tokens, at the cost of running another service. Turn
  self-service keys off with `EVERGARDEN_MAIL_UI_API_KEYS_ENABLED=false` if you
  do not want them.
- **Host access.** Anyone with your user account or root on the host can read
  the archive and the keys. Archived message text is protected by file
  permissions only (attachments are also encrypted). Use full-disk encryption
  and keep backups as private as the host.
- **Provider delays.** When an outcome is unknown, Evergarden waits and
  verifies rather than retrying blindly. You may see an item in "Verifying the
  result" for a while; that is the price of never sending twice.
- **Malicious verification codes.** A convincing phishing mail can contain a
  code. Only use a code for a sign-in you started yourself.
