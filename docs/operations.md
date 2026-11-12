# Operations

Commands run from the deployment root (the directory with
`docker-compose.yaml`, `.env` and `.local/`). Compose reads `.env` there, so
plain `docker compose ...` uses your project name, ports and profiles.

## Everyday commands

```bash
docker compose ps                         # state and health of every service
docker compose logs -f mcp                # follow one service's log
docker compose logs --since 1h approval-ui
docker compose restart mcp approval-ui mail-ui   # after a mailbox change
docker compose up -d                      # after editing runtime.env or .env
docker compose stop                       # stop without removing anything
```

Health endpoints (on the published loopback ports):

```bash
curl -s http://127.0.0.1:8788/gateway-healthz
curl -s http://127.0.0.1:8420/healthz     # mode, write switch, dispatcher state
curl -s http://127.0.0.1:8421/healthz
```

Logs never contain mail bodies, passwords or tokens.

## Upgrade

```bash
git pull
docker compose up -d --build
docker compose ps
```

`migrate` runs before the services that use the database and applies any new
migration; migrations are append-only. Setup does not rewrite an existing
`.local/run/runtime.env`, so compare it with `runtime.env.example` after an
upgrade and add new settings you want. Read [CHANGELOG.md](../CHANGELOG.md)
first.

To roll back the code, check out the previous version and run
`docker compose up -d --build` again. A database migration is not reversed by
this; if the release notes say a migration is not backwards compatible,
restore the database backup you took before upgrading.

## Back up and restore

Three things hold state:

| What | Where | Contains |
|---|---|---|
| Postgres volume | `<project>-postgres` (Docker volume) | Drafts, approvals, execution ledger, job history. |
| `.local/` | deployment root | Archive, encrypted credential store, keys, mailbox list, runtime.env, reports. |
| `.env` | deployment root | Project name, ports, profiles. |

`.local/run/credential_store_key` and `EVERGARDEN_HOST_ID` (in
`.local/run/runtime.env`) are needed to decrypt the credential store. Keep
backups as private as the host: they contain your mail and keys.

Back up:

```bash
docker compose exec -T postgres pg_dump -U evergarden -d evergarden --format=custom > evergarden.pgdump
docker compose stop
tar -czf evergarden-local.tgz .local .env
docker compose up -d
chmod 600 evergarden.pgdump evergarden-local.tgz
```

Stopping the stack while copying `.local/` gives a consistent copy of the
SQLite archive. The dump can be taken while the stack runs.

Restore on a new host (same or newer Evergarden version):

```bash
git clone https://github.com/Chivier/evergarden-mail.git evergarden && cd evergarden
tar -xzf /path/to/evergarden-local.tgz            # restores .local/ and .env
docker compose up -d postgres
docker compose exec -T postgres pg_restore -U evergarden -d evergarden --clean --if-exists < /path/to/evergarden.pgdump
docker compose up -d --build
```

Do not run `./deploy/setup` before restoring: it would create new keys. If your
user id differs on the new host, update `EVERGARDEN_UID` and `EVERGARDEN_GID`
in `.env`.

## Scheduled jobs

`config/jobs.yaml` defines the jobs. Cron expressions are evaluated in
`EVERGARDEN_SCHEDULE_TIMEZONE` (default UTC).

| Job | Schedule | What it does |
|---|---|---|
| `archive-sync` | minute 03 of every hour | Read-only sync of every enabled mailbox. |
| `oauth-watchdog` | minute 05 of every hour | Checks that every OAuth mailbox still has a usable token. |
| `weekly-rollover` | manual | Copies archive messages older than seven days into yearly archive files (copy only). |
| `cold-export` | manual | Writes a content-free inventory of the archive to the reports directory. |

Run them with one of:

- **The `scheduler` profile** (default after setup): a container that starts
  the due jobs every minute. Nothing else to do.
- **A systemd user timer** instead: run setup with `--no-scheduler` (or remove
  `scheduler` from `COMPOSE_PROFILES` in `.env`), then

  ```bash
  deploy/scripts/install_production_timer.sh
  systemctl --user enable --now evergarden-production-dispatch.timer
  ```

  The timer fires at minutes 03 and 05 and runs
  `docker compose run --rm worker python -m apps.worker.main due`. An
  `OnFailure` unit appends failures to `.local/data/reports/dispatch-failures.jsonl`
  and raises an alarm unit when a job fails twice in a row
  (`systemctl --user --failed`). If you change the schedules in `jobs.yaml`,
  change `OnCalendar` in the timer too. To keep it running after you log out,
  enable lingering (`loginctl enable-linger`).

Use one of the two, not both. Job leases make a double run harmless, but it
wastes a sync.

Run a manual job:

```bash
docker compose run --rm worker python -m apps.worker.main run weekly-rollover
docker compose run --rm worker python -m apps.worker.main run cold-export
```

A job that fails writes `.local/data/reports/<job>/<slot>.failed.json` with the
error class and the failed mailboxes, without mail content. One failed
`archive-sync` is not a problem: sync continues from its watermark, so the next
run catches up. Look into repeated failures of the same mailbox.

## Optional background services

Add them to `COMPOSE_PROFILES` in `.env` and run `docker compose up -d`.

- `oauth-maintenance`: refreshes OAuth tokens every five minutes and completes
  Microsoft device-code sign-ins in the background. It only runs when provider
  writes are enabled; on a read-only install it exits at startup.
- `mfa-autologin`: see [advanced/mfa-autologin.md](advanced/mfa-autologin.md).

## Reverse proxy and HTTPS

The gateway serves everything on one origin and is bound to `127.0.0.1:8788`.
For access from other machines, put a TLS reverse proxy in front of it. The
examples in [`deploy/reverse-proxy/`](../deploy/reverse-proxy/README.md) cover
Caddy, nginx and Nginx Proxy Manager.

1. Choose the public origin, for example `https://mail.example.com`.
2. On a fresh install run `./deploy/setup --public-origin https://mail.example.com`.
   This sets the MCP resource, the web origin, both OAuth redirect URIs and
   Secure cookies. On an existing install edit `.local/run/runtime.env`:

   ```dotenv
   EVERGARDEN_MCP_RESOURCE=https://mail.example.com/mcp
   EVERGARDEN_MAIL_UI_APPROVAL_URL=https://mail.example.com
   EVERGARDEN_MICROSOFT_OAUTH_REDIRECT_URI=https://mail.example.com/oauth/callback/microsoft
   EVERGARDEN_GOOGLE_OAUTH_REDIRECT_URI=https://mail.example.com/oauth/callback/google
   EVERGARDEN_ADMIN_SECURE_COOKIES=true
   ```

   then set the new resource as the `audience` of the `mail-ui` entry in
   `.local/run/compatibility_tokens.json` and run `docker compose up -d`.
3. Create new MCP API keys: keys are bound to the old resource URL. Update the
   redirect URIs registered with Microsoft or Google too.
4. Tell the gateway where the client address comes from, in `.env`
   (`./deploy/setup --real-ip` does it on a fresh install):

   ```dotenv
   EVERGARDEN_GATEWAY_REAL_IP=proxy        # or cloudflare behind Cloudflare
   #EVERGARDEN_GATEWAY_TRUSTED_PROXIES=<your proxy's address or network>   # optional
   ```

   then `docker compose up -d`. Without it every remote client shares the
   proxy's sign-in throttle bucket. See
   [configuration.md](configuration.md#real-client-address) for the modes and
   the rule that only the proxy may reach the gateway port.

Rules for every proxy: terminate TLS; forward `Host`, `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Forwarded-For`; do not buffer `/mcp` and allow long
reads there; allow request bodies up to 24 MiB on `/bridge/` if you use the
Thunderbird bridge; add no basic auth or forward-auth in front (Evergarden has
its own login and MCP uses bearer tokens).

To attach the gateway to an existing Docker network of your proxy instead of
publishing a port, set in `.env`:

```dotenv
COMPOSE_FILE=docker-compose.yaml:compose.proxy.yaml
EVERGARDEN_PROXY_NETWORK=<your proxy network>
EVERGARDEN_GATEWAY_REAL_IP=proxy
EVERGARDEN_GATEWAY_TRUSTED_PROXIES=<subnet of your proxy network>
```

The proxy then forwards to `http://evergarden-gateway:8080`. The overlay
removes the gateway's published host port, so only containers on the proxy
network reach it; `docker network inspect <your proxy network>` shows its
subnet.

## Reset the administrator password

```bash
python3 deploy/scripts/manage_admin_credentials.py --root . --username admin
docker compose restart mail-ui approval-ui
```

It prompts for a new password (12 to 1024 characters). With
`--generate-password --recovery-output .local/run/admin-recovery.txt` it
generates one and writes it to that mode-0600 file instead; move it to a
password manager and delete the file. Add `--rotate-session-key` to sign out
every browser as well.

## Renew the web UI's MCP token

The workbench's own MCP token is valid for 365 days. Every setup run prints its
expiry. Before it expires:

```bash
./deploy/setup --renew-mail-ui-grant
docker compose restart mcp
```

## Return failed actions for approval

When actions failed because the provider rejected them (for example during a
provider outage), this command creates fresh drafts for those that can still
be applied, after re-checking each message read-only. The originals stay in the
log as history.

```bash
docker compose exec mcp python -m deploy.scripts.return_failed_approvals          # preview
docker compose exec mcp python -m deploy.scripts.return_failed_approvals --apply
```

The new drafts appear under **Other pending operations** on the approval page.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `docker compose up` says `env file .../.local/run/runtime.env not found` | Setup has not run. Run `./deploy/setup`. |
| Setup fails with "owned by uid 0" or "is not a regular file" | The stack was started before setup and Docker created root-owned paths. Run `docker compose down`, remove or `chown` the named path, run setup again. |
| A container restarts and its log ends with a settings error | A value in `runtime.env` is invalid; the message names it. See [configuration.md](configuration.md). |
| Sign-in says "Too many attempts. Try again later." (HTTP 429) | The login throttle: 15 failures from one client address within 15 minutes by default. In the default `direct` gateway mode behind a reverse proxy, everyone shares the proxy's address; set `EVERGARDEN_GATEWAY_REAL_IP` (see [configuration.md](configuration.md#real-client-address)). Wait for the window to pass, or clear the counters with `docker compose restart mail-ui`. |
| Every page sends you to the sign-in page and signing in fails with HTTP 503 | The sign-out record `.local/run/mail-config/admin_session_revocations.json` has the wrong mode or is damaged. Delete it (see [security.md](security.md#browser-sessions-and-sign-in)). |
| Sign-out shows `LOGOUT_NOT_RECORDED` | The web UI could not write the sign-out record (for example `.local/run/mail-config` is not writable by `EVERGARDEN_UID`). This browser is signed out, other sessions are not. Fix the permissions and sign in and out again. |
| HTTP 502 from the public URL right after an upgrade or `docker compose up` | The gateway container was recreated and got a new address, but the reverse proxy resolved `evergarden-gateway` once at start-up (Nginx Proxy Manager and plain nginx do this). Reload the proxy, for example `docker exec <npm-container> nginx -s reload`. |
| The gateway restarts and its log starts with `evergarden-gateway:` | `EVERGARDEN_GATEWAY_REAL_IP` or `EVERGARDEN_GATEWAY_TRUSTED_PROXIES` in `.env` is invalid; the message names the value. |
| "Microsoft sign-in is not configured yet" on the connect page | `EVERGARDEN_MICROSOFT_OAUTH_CLIENT_ID` is still the placeholder. See [providers.md](providers.md#outlookcom-and-microsoft-365). |
| "No Google OAuth app is configured yet" | Import your Google client with `set-google-client`; see [providers.md](providers.md#with-your-own-google-oauth-client). |
| "The Google OAuth client does not list the current redirect URI" | Add `EVERGARDEN_GOOGLE_OAUTH_REDIRECT_URI` to the client in Google Cloud, download the JSON again and re-import. |
| Sync fails with an authentication error | Wrong password: run `set-password` again. OAuth mailbox: `oauth_status` shows `authorization_required`; connect it again from **Manage mailboxes**. |
| Sync fails with `gaierror` or a connection timeout | Wrong IMAP host or port, or no internet from the `mcp` container. |
| Executing an approval fails with `side effect fence rejected: external side effects are disabled` | Provider writes are off. Set `EVERGARDEN_SIDE_EFFECTS_ENABLED=true` and run `docker compose up -d`. |
| `... reversible Trash actions are disabled` | Set `EVERGARDEN_TRASH_ACTIONS_ENABLED=true` as well. |
| Approving says "The auto-run service is not running or does not handle this kind of operation, so approvals are paused." | The dispatcher is enabled but cannot run this kind: writes are off, Trash is off for a Trash draft, or the `mcp` service is down. Fix the cause or set `EVERGARDEN_APPROVAL_DISPATCH_ENABLED=false`. |
| An item stays in "Verifying the result" | The outcome is unknown and being checked read-only; it settles within 24 hours. Do not create a new draft for the same change meanwhile. |
| A new mailbox does not appear | Restart `mcp approval-ui mail-ui` after every mailbox change. |
| A client gets HTTP 401 after you changed the origin | Keys are bound to `EVERGARDEN_MCP_RESOURCE`; create new ones. |
| `oauth-maintenance` keeps restarting | It requires provider writes to be enabled. Remove it from `COMPOSE_PROFILES` on a read-only install. |
