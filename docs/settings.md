# Web settings

Sign in and open **Settings** in the workbench sidebar. The **+** beside
Mailboxes also opens **Settings → Mailboxes**. English, Simplified Chinese,
dark mode and mobile layouts are supported.

## Mailboxes

Use **Add a mailbox**, **Edit**, **Enable/Disable** or **Remove mailbox** on a
mailbox card. You can edit the sign-in address, allowed From identities,
IMAP/SMTP hosts, ports and TLS mode, authentication, credential record,
provider and folder mappings. The alias cannot be renamed because it
identifies archived mail. Existing passwords are kept when saving the form;
credential records must remain unique. Changing a credential record selects
a different stored credential and may require signing in again.

For password authentication, save the mailbox, then choose **Set app password**.
The backend encrypts it in the existing credential store and never returns it.
For OAuth, restart after adding/changing the mailbox and use **Connect OAuth**.
Google still requires your own OAuth application to be imported as described in
[Providers](providers.md).

Removal deletes only the configuration entry, after confirmation. Synced mail,
encrypted credentials, approvals and provider mail are preserved. Disable is
reversible and retains the configuration entry too. Configuration changes take
effect on restart; already running operations can finish before that restart.

## Apply configuration changes

Mailbox and runtime changes are saved to private mode-0600 files under
`.local/run/mail-config/`. Run from the deployment directory:

```bash
docker compose run --rm migrate
docker compose restart mcp approval-ui mail-ui
```

Also restart the optional services you run: `scheduler`, `oauth-maintenance`
and/or `mfa-autologin`. A one-shot worker reads new settings on its next run.
The migration command reconciles writer controls before apps restart. The
settings page marks runtime fields that differ from the web process's active
configuration as waiting for restart. It cannot check whether every other
service has restarted. Password and API-key changes are available immediately.

The page does not get access to Docker's socket. Restart commands remain an
operator action. Back up `.local/run/mail-config/` and the encrypted credential
store before changing production configuration.

## Runtime configuration

**Runtime configuration** covers sign-in limits (15 failures by default),
session lifetime, schedule timezone, log level, review windows, provider sign-in
settings and mail write/approval policies. Permission changes require explicit
confirmation. Trash always needs human approval; permanent message deletion
stays unavailable.

Values are validated together before an atomic write and override the matching
`EVERGARDEN_*` variables at startup. This does not rewrite `runtime.env` or
Compose's `.env`. Deployment identity, writer identity/epoch, database access,
paths, secrets, ports and feature gates stay under server control. To return a
setting to environment-file control, stop application writers, back up
`runtime-settings.json`, remove that key from its `values` object and restart.

Concurrent edits use revision checks. If another tab saved first, reload before
editing again. Invalid settings leave the saved file unchanged. Do not rerun
SOPS materialization to apply web edits: it regenerates the mailbox inventory
from the encrypted source; reconcile that source first if you use both.

Configuration editing uses `EVERGARDEN_MAIL_UI_ACCOUNT_ADMIN_ENABLED`, enabled
by setup. API key issuance has its own `EVERGARDEN_MAIL_UI_API_KEYS_ENABLED`
switch. Both remain operator-controlled gates.

## API keys

Create a separate key for each client, select only its required scopes and
choose 30, 90 or 365 days, or **Never expires**. A permanent key requires checking
the risk acknowledgement: a leaked token keeps granting its permissions until
you revoke it. Existing keys retain their expiry; their lifetime is not changed
by this update.

Plaintext is shown once, cleared when you leave the API-key tab or close its
output, and never stored in browser storage. The server stores only a hash.
**Revoke** invalidates both expiring and permanent keys immediately without an
MCP restart. To change an existing key's lifetime, create a replacement, update
the client and revoke the old key.

For advanced SOPS deployments, `materialize_secrets.py` defaults to 365-day
compatibility grants. `--token-ttl-days 0 --acknowledge-no-expiry` explicitly
requests permanent grants; the flag acknowledges the same leak/revocation risk.
