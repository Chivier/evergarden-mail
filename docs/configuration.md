# Configuration reference

Evergarden reads its base settings from two files. `./deploy/setup` writes both.
The [web settings page](settings.md) can save overrides for supported application
settings in `.local/run/mail-config/runtime-settings.json`. These overrides take
precedence at application startup; they are private and never contain credentials.

| File | Read by | Contains |
|---|---|---|
| `.env` (template [`.env.example`](../.env.example)) | Docker Compose only | Project name, images, host ports, UID/GID, compose profiles. These values fill `${...}` placeholders in `docker-compose.yaml` and never reach the containers. |
| `.local/run/runtime.env` (template [`runtime.env.example`](../runtime.env.example)) | Every Evergarden container (`env_file`) | Application settings: the write switch, URLs, OAuth, optional components. |

Secrets are never in either file. Each secret is a file under `.local/run/`
that `docker-compose.yaml` mounts read-only; the settings below only name the
path inside the container.

After editing `runtime.env`, run `docker compose up -d`. Compose sees the
changed file, recreates the containers and runs the `migrate` service again,
which also records the writer settings in the database.

Rules that apply to every setting:

- Names are case-insensitive and start with `EVERGARDEN_`.
- An empty value (`KEY=`) or a commented-out line means "not set": the default
  in the table applies. The exception is `EVERGARDEN_HOST_ID`: an empty value
  is an error, so a deleted value cannot silently change the identity bound into
  your encrypted credentials.
- An invalid value stops the service at startup with a message naming the
  problem. Check `docker compose logs <service>`.
- The defaults in the table are the code defaults, chosen to be safe for a
  stranger who sets nothing (writes off, web surfaces off). `runtime.env.example`
  turns the web surfaces on and points the paths at the mounted files.

## Compose-level variables (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `EVERGARDEN_COMPOSE_PROJECT` | `evergarden` | Compose project name. Container, network and volume names derive from it, including the Postgres volume `<project>-postgres`. Choose it once. |
| `EVERGARDEN_UID`, `EVERGARDEN_GID` | `1000` | Host user and group the application containers run as, so they can read the private files in `.local/`. Setup writes the output of `id -u` / `id -g`. |
| `COMPOSE_PROFILES` | `scheduler` (written by setup) | Optional services: `scheduler` (runs due jobs every minute), `oauth-maintenance` (keeps OAuth tokens fresh), `mfa-autologin` (see [advanced/mfa-autologin.md](advanced/mfa-autologin.md)). Comma-separated. |
| `COMPOSE_FILE` | unset | Set to `docker-compose.yaml:compose.proxy.yaml` to attach the gateway to an existing reverse-proxy network. |
| `EVERGARDEN_PROXY_NETWORK` | `proxy` | External network that `compose.proxy.yaml` joins. It must already exist. |
| `EVERGARDEN_IMAGE` | `evergarden:local` | Image built by `docker compose build` for the application services. |
| `EVERGARDEN_AUTOLOGIN_IMAGE` | `evergarden-autologin:local` | Image of the optional `mfa-autologin` service. |
| `EVERGARDEN_HTTP_BIND`, `EVERGARDEN_HTTP_PORT` | `127.0.0.1`, `8788` | Gateway: the web UI, approval pages and `/mcp` on one origin. |
| `EVERGARDEN_MCP_BIND`, `EVERGARDEN_MCP_PORT` | `127.0.0.1`, `8420` | Direct MCP endpoint (`/mcp`), bypassing the gateway. |
| `EVERGARDEN_APPROVAL_BIND`, `EVERGARDEN_APPROVAL_PORT` | `127.0.0.1`, `8421` | Direct approval UI. |
| `EVERGARDEN_GATEWAY_REAL_IP` | `direct` | Where the gateway takes the client address from: `direct`, `proxy` or `cloudflare`. See [Real client address](#real-client-address). An unknown value stops `docker compose` before anything starts. |
| `EVERGARDEN_GATEWAY_TRUSTED_PROXIES` | loopback, RFC 1918, `fc00::/7` | Reverse proxies trusted in `proxy` and `cloudflare` mode: addresses or CIDRs separated by commas, or `none`. Unset or empty means `127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7`. |

Keep the binds on `127.0.0.1`. For access from other machines put a TLS
reverse proxy in front of the gateway; see [operations.md](operations.md#reverse-proxy-and-https).

### Real client address

The gateway sends the apps exactly one `X-Forwarded-For` address: the client
it resolved. The web UI keys its login throttle on that address, and the
gateway's access log shows it. Pick the mode that matches what sits in front
of the gateway:

| Mode | Use when | Client address |
|---|---|---|
| `direct` (default) | Nothing in front: you open `http://127.0.0.1:8788` yourself. | The TCP peer of the gateway. `X-Forwarded-For`, `CF-Connecting-IP` and every other forwarding header are ignored. |
| `proxy` | A reverse proxy (Caddy, nginx, Nginx Proxy Manager, Traefik, a `cloudflared` tunnel container) forwards to the gateway. | The right-most `X-Forwarded-For` entry that is not a trusted proxy (nginx `real_ip_recursive`). A request from a peer that is not a trusted proxy keeps that peer as the client; its headers are ignored. |
| `cloudflare` | Cloudflare proxies your domain, either straight to the gateway or through your own reverse proxy. | As in `proxy` mode, then: if the resolved hop is a [Cloudflare edge address](https://www.cloudflare.com/ips/), the address in `CF-Connecting-IP`. The header counts only when it holds exactly one IPv4 or IPv6 address; anything else keeps the hop. From any other hop it is ignored, so a client that bypasses Cloudflare cannot forge it. |

In `direct` mode behind a reverse proxy, every remote client appears as the
proxy and shares one throttle bucket, so a stranger who guesses wrong can lock
you out for the throttle window. Setup prints a warning when the public origin
is `https://` and the mode is `direct`.

**Exposure rule for `proxy` and `cloudflare`.** Anything that reaches the
gateway port from a trusted range can claim any client address. Only the proxy
may reach it: while a trusted-proxy list is in effect (the default list or your
own, anything but `none`), never set `EVERGARDEN_HTTP_BIND` to `0.0.0.0` or a
LAN address, and narrow `EVERGARDEN_GATEWAY_TRUSTED_PROXIES` to your proxy's
address or Docker network when you can (for example the subnet shown by
`docker network inspect <proxy network>`). A proxy on the same host that
connects to the published loopback port reaches the gateway from the Docker
bridge address, which the default list trusts; every local user of the host
can then do the same.

Notes on specific setups:

- **Cloudflare straight to the gateway** (the gateway port published on a
  public address, Cloudflare as the only client): the peer is a Cloudflare
  edge, `CF-Connecting-IP` is used. Set `EVERGARDEN_GATEWAY_TRUSTED_PROXIES=none`
  so no private-range peer is trusted; this is the one case where a public
  bind is acceptable, because no peer's `X-Forwarded-For` is trusted and a
  non-Cloudflare peer cannot forge `CF-Connecting-IP`. The gateway speaks
  plain HTTP, so Cloudflare's connection to it is unencrypted. Restrict the
  port to [Cloudflare's ranges](https://www.cloudflare.com/ips/) in the
  `DOCKER-USER` iptables chain or in an upstream (cloud or network) firewall:
  ports published by Docker bypass ordinary host `INPUT` rules and `ufw`.
  Prefer a TLS reverse proxy in front (Cloudflare "Full (strict)") or a
  `cloudflared` tunnel over exposing the plaintext port.
- **Cloudflare, then your reverse proxy** (for example Nginx Proxy Manager on a
  Docker network): the proxy must pass `CF-Connecting-IP` through unchanged and
  replace `X-Forwarded-For` with the address it saw (the Cloudflare edge), as
  Nginx Proxy Manager does. The gateway resolves the edge, then
  `CF-Connecting-IP`. A proxy that appends instead is safe only when
  `EVERGARDEN_GATEWAY_TRUSTED_PROXIES` is narrowed to the proxy's own address
  or network (see the proxy rules in `deploy/reverse-proxy/README.md`).
- **`cloudflared` tunnel container**: it connects from a private Docker address
  and sends the visitor's address in both `X-Forwarded-For` and
  `CF-Connecting-IP`. `proxy` mode resolves the visitor from
  `X-Forwarded-For`; `cloudflare` mode gives the same result.
- The Cloudflare ranges ship in `deploy/nginx/real-ip/cloudflare-ranges.conf`
  with the date they were fetched. Refresh them with
  `python3 deploy/scripts/update_cloudflare_ranges.py` and
  `docker compose restart gateway`.

An invalid trusted-proxy entry (a host name, a malformed address, a `/0`
network) stops the gateway at start with a message in
`docker compose logs gateway`; it never falls back to another mode.

## `./deploy/setup` options

| Option | Effect |
|---|---|
| `--public-origin URL` | Origin browsers and MCP clients use. Default `http://127.0.0.1:<http-port>`. A non-loopback origin must be `https://` and turns on Secure cookies. |
| `--http-port`, `--mcp-port`, `--approval-port` | Host ports written to `.env`. |
| `--real-ip MODE` | Value of `EVERGARDEN_GATEWAY_REAL_IP`: `direct` (default), `proxy` or `cloudflare`. Asked interactively when the public origin is `https://`. |
| `--trusted-proxies CIDRS` | Value of `EVERGARDEN_GATEWAY_TRUSTED_PROXIES` (with `--real-ip proxy` or `cloudflare` only), for example the subnet of your proxy's Docker network, or `none`. |
| `--host-id ID` | Value of `EVERGARDEN_HOST_ID`. Default `default`, the same as the code default; the machine's host name is never used. Keep it once mailboxes are stored. |
| `--admin-user NAME` | Administrator username (default `admin`). |
| `--project NAME` | Value of `EVERGARDEN_COMPOSE_PROJECT`. |
| `--no-scheduler` | Leave `COMPOSE_PROFILES` empty (use a host timer instead). |
| `--renew-mail-ui-grant` | Extend the web UI's internal MCP token by 365 days. |
| `--non-interactive` | Never prompt. Without it, setup asks for the public origin and username when run in a terminal for the first time. |
| `--root DIR` | Deployment root (default: the clone). |

Setup never overwrites an existing file, so running it again only fills in
what is missing. That includes `.env`: on an existing install `--real-ip`
only prints a reminder; set `EVERGARDEN_GATEWAY_REAL_IP` in `.env` yourself and
run `docker compose up -d`.

## Application settings (`runtime.env`)

"Used by" names the Compose services whose behaviour the setting changes
(`worker` also stands for the `scheduler` service, which runs the same jobs).
Every container reads the whole file. The table is generated from
`evergarden/config.py` by `tools/gen_config_docs.py`.

<!-- BEGIN SETTINGS TABLE (generated by tools/gen_config_docs.py) -->

### Identity and writes

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `EVERGARDEN_HOST_ID` | `default` | all | Stable name of this deployment. Bound into the encryption of stored credentials and approvals: never change it once mailboxes are stored. `none` is reserved. |
| `EVERGARDEN_ACTIVE_WRITER` | unset | migrate, mcp, worker | The one host id allowed to write. Unset means this host; `none` forbids writes. |
| `EVERGARDEN_WRITER_EPOCH` | `1` | migrate, mcp, worker | Must match the database writer-control row (the `migrate` service records it). Raising it fences out older processes still running with the previous value. |
| `EVERGARDEN_SIDE_EFFECTS_ENABLED` | `false` | migrate, mcp, worker, oauth-maintenance, mfa-autologin | The write switch. `false` keeps the install read-only: no send, move, mark or Trash reaches a provider. |
| `EVERGARDEN_TRASH_ACTIONS_ENABLED` | `false` | mcp | Separate switch for moving mail to Trash. Trash always needs a human approval. |
| `EVERGARDEN_APPROVAL_DISPATCH_ENABLED` | `false` | mcp, approval-ui | Run human approvals in the background in the MCP service. Off: the client that prepared the draft runs it with the matching `*_approved` tool. |
| `EVERGARDEN_APPROVAL_DISPATCH_PARALLEL` | `4` | mcp | Mailboxes the background dispatcher works on at the same time (1-8). |
| `EVERGARDEN_UIDPLUS_MOVE_ACCOUNTS` | empty | mcp, approval-ui | Account aliases without IMAP MOVE that may move with UID COPY, a verified copy, then UID EXPUNGE of that one message (for example iCloud). |
| `EVERGARDEN_AUTO_APPROVE` | empty | mcp | Comma-separated intent kinds approved at preparation time without a human: any of `send`, `archive`, `move`, `mark`, or `all`. `trash` is refused at startup. |
| `EVERGARDEN_SCHEDULE_TIMEZONE` | `UTC` | worker, scheduler | IANA timezone in which `config/jobs.yaml` schedules are evaluated. |
| `EVERGARDEN_APPROVAL_DRAFT_LIFETIME_HOURS` | `6` | mcp | How long a draft waits for a human review (1-72). A human approval itself never expires. |

### Storage

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `EVERGARDEN_DATABASE_URL` | `postgresql://evergarden@postgres:5432/evergarden` | migrate, mcp, approval-ui, worker | PostgreSQL URL. The password comes from the mounted pgpass file, not the URL. |
| `EVERGARDEN_ARCHIVE_DIR` | `/data/archive` | mcp, approval-ui, mail-ui, worker | Mail archive directory. |
| `EVERGARDEN_REPORT_DIR` | `/data/reports` | worker, mfa-autologin | Job reports, failure reports and MFA auto-login screenshots. |
| `EVERGARDEN_CREDENTIAL_DB` | `/data/secrets/credentials.db` | mcp, approval-ui, worker | Encrypted credential store (mailbox passwords, OAuth tokens, notes). |
| `EVERGARDEN_CREDENTIAL_KEY_FILE` | `/run/secrets/credential_store_key` | mcp, approval-ui, mail-ui, worker | Key file of the credential store. Losing it loses every stored credential. |
| `EVERGARDEN_ACCOUNT_CONFIG_FILE` | unset | mcp, approval-ui, mail-ui, worker | Mailbox inventory JSON (no passwords). Unset means no mailboxes. |

### MCP authentication

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `EVERGARDEN_MCP_RESOURCE` | `https://evergarden.example.invalid/mcp` | mcp, mail-ui | Public URL of the MCP endpoint and the audience of every bearer token. HTTPS, or loopback HTTP. The code default is a placeholder; setup writes the real value. |
| `EVERGARDEN_OAUTH_ISSUER` | `https://auth.example.invalid` | mcp, mail-ui | External OAuth authorization server. Advertised to MCP clients (protected-resource metadata, `WWW-Authenticate`, the web UI's OAuth guide) and trusted only when JWKS or introspection is also configured; otherwise it is ignored. |
| `EVERGARDEN_OAUTH_JWKS_URL` | unset | mcp | JWKS URL for verifying JWT access tokens from the issuer. |
| `EVERGARDEN_OAUTH_INTROSPECTION_URL` | unset | mcp | Token introspection endpoint (needs the client id and secret file too). |
| `EVERGARDEN_OAUTH_INTROSPECTION_CLIENT_ID` | unset | mcp | Introspection client id. |
| `EVERGARDEN_OAUTH_INTROSPECTION_CLIENT_SECRET_FILE` | unset | mcp | File holding the introspection client secret. |
| `EVERGARDEN_COMPATIBILITY_TOKEN_FILE` | unset | mcp | Static token registry (SHA-256 hashes). Setup puts the mail UI's own grant here. |
| `EVERGARDEN_MCP_API_KEYS_FILE` | unset | mcp, mail-ui | Registry of API keys created in the mail UI. MCP reloads it when it changes. |

### Provider OAuth

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `EVERGARDEN_MICROSOFT_OAUTH_CLIENT_ID` | `replace-with-public-client-id` | approval-ui, mcp, worker | Client id of your own Microsoft Entra app. The placeholder is rejected at sign-in. |
| `EVERGARDEN_MICROSOFT_OAUTH_TENANT` | `common` | approval-ui, mcp, worker | Entra tenant: `common`, `consumers`, `organizations` or a tenant id. |
| `EVERGARDEN_MICROSOFT_OAUTH_REDIRECT_URI` | `http://127.0.0.1:8788/oauth/callback/microsoft` | approval-ui | Redirect URI registered in the Entra app (authorization code flow). |
| `EVERGARDEN_GOOGLE_OAUTH_REDIRECT_URI` | `http://127.0.0.1:8788/oauth/callback/google` | approval-ui | Redirect URI registered in your Google OAuth web client. |
| `EVERGARDEN_MICROSOFT_OAUTH_FLOW` | `authorization_code` | approval-ui, oauth-maintenance, mfa-autologin | `authorization_code` (redirect back to Evergarden) or `device_code` (enter a code on Microsoft's page). |
| `EVERGARDEN_MICROSOFT_OAUTH_APP_NAME` | empty | approval-ui, mfa-autologin | Display name of the Entra app as Microsoft shows it. Optional; MFA auto-login needs it. |

### Web surfaces and login

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `EVERGARDEN_ADMIN_CREDENTIAL_FILE` | unset | mail-ui | Administrator credential (scrypt hash) written by setup. |
| `EVERGARDEN_ADMIN_SESSION_KEY_FILE` | unset | mail-ui, approval-ui | Key that signs administrator sessions. Replacing it signs everyone out. |
| `EVERGARDEN_ADMIN_SESSION_TTL_SECONDS` | `604800` | mail-ui, approval-ui | Session lifetime in seconds (300 to 2592000, i.e. 30 days). |
| `EVERGARDEN_ADMIN_SESSION_REVOCATION_FILE` | `/run/mail-config/admin_session_revocations.json` | mail-ui, approval-ui | Per-administrator sign-out times (mode 0600 JSON). Logout in the web UI records one here, ending every session of that administrator on all devices; the mail UI writes it, the approval UI reads it. Missing means nobody has signed out; a file with the wrong mode or bad content rejects every session (see docs/security.md). |
| `EVERGARDEN_ADMIN_LOGIN_MAX_FAILURES` | `15` | mail-ui | Failed sign-ins allowed per client address and window before HTTP 429 (3-20). The address is the one the gateway resolves (IPv6 clients count per /64); see `EVERGARDEN_GATEWAY_REAL_IP`. |
| `EVERGARDEN_ADMIN_LOGIN_WINDOW_SECONDS` | `900` | mail-ui | Length of the failed sign-in window in seconds (60-3600). |
| `EVERGARDEN_ADMIN_SECURE_COOKIES` | `true` | mail-ui, approval-ui | Mark session cookies Secure; the cookie is then named `__Host-evergarden_admin_session`. `false` is only accepted for a loopback `http://` origin. |
| `EVERGARDEN_APPROVAL_UI_ENABLED` | `false` | approval-ui | Serve the approval pages. |
| `EVERGARDEN_OAUTH_CALLBACK_ENABLED` | `false` | approval-ui, oauth-maintenance, mfa-autologin | Serve the mailbox OAuth pages (`/oauth`). |
| `EVERGARDEN_MAIL_UI_ENABLED` | `false` | mail-ui | Serve the mail workbench. |
| `EVERGARDEN_MAIL_UI_MCP_URL` | `http://mcp:8000/mcp` | mail-ui | Internal MCP URL the workbench calls. |
| `EVERGARDEN_MAIL_UI_MCP_TOKEN_FILE` | unset | mail-ui | The workbench's own MCP token, written by setup. |
| `EVERGARDEN_MAIL_UI_APPROVAL_URL` | `http://127.0.0.1:8788` | mail-ui | Public browser origin of the web UI; links to approval pages use it. |
| `EVERGARDEN_MAIL_UI_ACCOUNT_ADMIN_ENABLED` | `false` | mail-ui | Allow adding and disabling mailboxes under "Manage mailboxes". |
| `EVERGARDEN_MAIL_UI_API_KEYS_ENABLED` | `false` | mail-ui | Allow creating and revoking MCP API keys under "Connect an MCP agent". |
| `EVERGARDEN_LOG_LEVEL` | `INFO` | all | Python log level. |

### Optional components

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `EVERGARDEN_THUNDERBIRD_BRIDGE_ACCOUNTS` | empty | mcp, mail-ui | Account aliases that receive mail through the Thunderbird bridge. They are receive-only: every write to them is refused. |
| `EVERGARDEN_THUNDERBIRD_BRIDGE_CLIENTS_FILE` | `/run/mail-config/thunderbird-bridge-clients.json` | mail-ui | Registry of paired Thunderbird bridge clients (hashes only). |
| `EVERGARDEN_MFA_AUTOLOGIN_ENABLED` | `false` | mfa-autologin | Opt-in switch for the MFA auto-login component (see docs/advanced/mfa-autologin.md). |
| `EVERGARDEN_MFA_EXTRA_ALLOWED_HOSTS` | empty | mfa-autologin | Comma-separated identity-provider hosts (for example an organisation's ADFS) the sign-in browser may visit besides Microsoft's own. |
| `EVERGARDEN_MFA_BROWSER_LOCALE` | `en-US` | mfa-autologin | Browser locale for the sign-in pages. Their text is matched in English. |

<!-- END SETTINGS TABLE -->

## Sign-in and session defaults

The table shows code defaults. What a new install actually runs with:

| Setting | Code default | `./deploy/setup` (from `runtime.env.example`) | `deploy/scripts/materialize_secrets.py` (SOPS path) |
|---|---|---|---|
| `EVERGARDEN_ADMIN_SESSION_TTL_SECONDS` | `604800` (7 days) | `604800` | `604800` |
| `EVERGARDEN_ADMIN_LOGIN_MAX_FAILURES` | `15` | `15` | `5` |
| `EVERGARDEN_ADMIN_LOGIN_WINDOW_SECONDS` | `900` (15 minutes) | `900` | `900` |

`deploy/scripts/manage_admin_credentials.py` adds the same three values as
setup (`604800`, `15`, `900`) only when `runtime.env` lacks them. Sessions can
last at most 30 days (`2592000`). The throttle counts failed sign-ins per
client address, as resolved by the gateway (see
[Real client address](#real-client-address)); after the limit the web UI
answers HTTP 429 with `Retry-After` until the oldest failure leaves the window.
A successful sign-in clears that address's count, and
`docker compose restart mail-ui` clears all of them.

## Mailbox inventory

Mailboxes live in `.local/run/mail-config/mail_accounts.json`
(`EVERGARDEN_ACCOUNT_CONFIG_FILE`). Add them in the web UI ("Manage
mailboxes") or edit the file; see [providers.md](providers.md#mailbox-fields)
for the fields. The file never holds a password or token.
