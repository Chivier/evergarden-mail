# Mail providers

Evergarden talks to mailboxes over IMAP (read and organize) and SMTP (send). A
mailbox signs in either with a password (usually an app password) or with
OAuth. Password mailboxes need no extra setup. OAuth mailboxes need an OAuth
app that you register with the provider yourself; Evergarden ships no shared
client id.

| Provider | Sign-in | Native IMAP MOVE | Notes |
|---|---|---|---|
| Any IMAP/SMTP server | password | depends on the server | [Generic IMAP](#generic-imap-and-smtp) |
| Gmail / Google Workspace | app password, or OAuth with your own Google Cloud client | yes | [Gmail](#gmail-and-google-workspace) |
| iCloud Mail | app-specific password | no (UIDPLUS move or copy fallback) | [iCloud](#icloud-mail) |
| Outlook.com / Microsoft 365 | OAuth with your own Microsoft Entra app | yes | [Microsoft](#outlookcom-and-microsoft-365) |

## Adding a mailbox

1. In the workbench click **+** next to **Mailboxes** ("Manage mailboxes"),
   expand **Add a mailbox**, fill in the form and click **Save private
   configuration**. The form writes `.local/run/mail-config/mail_accounts.json`
   and never accepts a password or token.
2. Store the credential:
   - Password mailbox:
     `docker compose exec approval-ui evergarden-provider-credential set-password --account <alias>`
   - OAuth mailbox: see the provider section below.
3. Restart the services that read the mailbox list:
   `docker compose restart mcp approval-ui mail-ui`.
4. Click **Sync mail** in the workbench.

`docker compose exec approval-ui evergarden-provider-credential status` shows
which mailboxes have a stored credential, without printing it.

The web UI can add and disable mailboxes but not edit them. To change a host,
port or folder, edit `mail_accounts.json` (keep it mode 0600) and restart the
three services. **Disable (keep data)** deactivates a mailbox; its archive,
credential and preferences stay, and **Enable again** brings it back. There
is no command that deletes a mailbox's data.

The command-line equivalent is `evergarden-account-config`:

```bash
docker compose exec mail-ui evergarden-account-config \
  --config /run/mail-config/mail_accounts.json list
docker compose exec -T mail-ui evergarden-account-config \
  --config /run/mail-config/mail_accounts.json add --expected-revision <revision> < account.json
docker compose exec mail-ui evergarden-account-config \
  --config /run/mail-config/mail_accounts.json set-enabled <alias> --enabled false --expected-revision <revision>
```

`list` prints the current revision; `add` reads one account object (the fields
below) on standard input.

### Mailbox fields

| Field | Meaning |
|---|---|
| `alias` | Lowercase name (`[a-z][a-z0-9_-]*`) used in commands and tool calls. Do not reuse an alias. |
| `address` | Sign-in address for IMAP, SMTP and OAuth. |
| `send_from_addresses` | Allowed visible From addresses; the first is the default and the list must include `address`. A send from an address the provider does not let you use fails; Evergarden never falls back to another address. |
| `imap_host`, `imap_port` | IMAP server, TLS (usually port 993). |
| `smtp_host`, `smtp_port`, `smtp_mode` | SMTP server; `smtp_mode` is `starttls` (usually 587) or `ssl` (implicit TLS, usually 465). |
| `auth_kind` | `password` or `oauth2`. For `oauth2`, `imap.gmail.com` means Google; any other host means Microsoft. |
| `credential_record` | Stable id of the credential in the encrypted store, for example `password:personal`, `google:work`, `microsoft:work`. Not a secret. |
| `folders` | Folders to sync. |
| `archive_folder` | Destination of Archive. Must also be in `safe_move_folders`. |
| `sent_folder` | Where a sent message's copy is checked (and appended once if the provider did not save it). |
| `trash_folder` | Destination of Move to trash. Must not be in `safe_move_folders`. |
| `safe_move_folders` | Allowed destinations of an ordinary move. Trash, Bin, Deleted, Junk and Spam folders are refused. |
| `copy_preserve_source_fallback` | For servers without IMAP MOVE: Archive and Move copy the message and mark the original read, leaving it in place. Never used for Trash. |
| `enabled` | `false` disables the mailbox and keeps its data. |
| `provider` | Optional: `gmail`, `microsoft`, `icloud` or `imap`. Normally detected from the IMAP host. |

[`config/mail-accounts.example.json`](../config/mail-accounts.example.json) is a
complete example.

### Servers without IMAP MOVE

Ordinary moves and Trash use IMAP `MOVE`. For a server without it, choose one
of two options per mailbox (not both):

- **UIDPLUS move**: list the alias in `EVERGARDEN_UIDPLUS_MOVE_ACCOUNTS` in
  `runtime.env`. If the server supports UIDPLUS, Evergarden copies the message,
  verifies the copy, then flags and expunges only that one original
  (`UID EXPUNGE <uid>`). This is a real move and also works for Trash.
- **Copy fallback**: set `copy_preserve_source_fallback` to `true`. Archive and
  Move copy the message and leave the original (marked read) in the source
  folder. Trash is not available.

Evergarden never runs a plain `EXPUNGE`, never empties Trash and never deletes
permanently.

## Generic IMAP and SMTP

Any server with TLS IMAP and SMTP and password sign-in works. Use the account
password or, where the provider offers one, an app password. Look up the host
names, ports and exact folder names in your provider's documentation; folder
names are case-sensitive and differ between providers (`Sent`, `Sent Items`,
`Sent Messages`, ...).

## Gmail and Google Workspace

Settings for both sign-in methods:

| Field | Value |
|---|---|
| IMAP | `imap.gmail.com`, port `993` |
| SMTP | `smtp.gmail.com`, port `465`, Implicit TLS |
| Folders to sync | `INBOX` |
| Archive folder | `[Gmail]/All Mail` (also in Allowed move destinations) |
| Sent folder | `[Gmail]/Sent Mail` |
| Trash folder | `[Gmail]/Trash` |

Accounts whose folders appear as `[Google Mail]/...` use that prefix instead.
Gmail labels are IMAP folders; Archive moves a message out of the Inbox into
All Mail, which is Gmail's archive.

### With an app password

1. Turn on 2-Step Verification for the Google account.
2. Create an app password at <https://myaccount.google.com/apppasswords>.
   A Google Workspace administrator can disable app passwords; use OAuth then.
3. Add the mailbox with **Authentication: App password** and store the app
   password with `set-password`.

### With your own Google OAuth client

1. In the [Google Cloud console](https://console.cloud.google.com/), create or
   pick a project and configure the OAuth consent screen (Google Auth
   Platform). For a Workspace domain used only by its own users, choose
   **Internal**.
   An **External** app left in **Testing** issues refresh tokens that expire
   after seven days, so you would have to reconnect weekly.
2. Create an OAuth client of type **Web application**. Add the exact value of
   `EVERGARDEN_GOOGLE_OAUTH_REDIRECT_URI` from `.local/run/runtime.env` as an
   authorized redirect URI (setup writes `<origin>/oauth/callback/google`).
3. The scopes Evergarden requests are `openid`, `email` and
   `https://mail.google.com/` (needed for IMAP and SMTP).
4. Download the client JSON and import it into the encrypted credential store:

   ```bash
   install -d -m 700 .local/run/google-oauth-import
   install -m 600 ~/Downloads/client_secret_XXXX.json .local/run/google-oauth-import/client.json
   docker compose run --rm --no-deps \
     -v "$PWD/.local/run/google-oauth-import:/run/google-oauth-import:ro" \
     approval-ui evergarden-provider-credential set-google-client \
     --client-file /run/google-oauth-import/client.json
   rm .local/run/google-oauth-import/client.json
   ```

   The import refuses a file readable by others, a client that is not a Web
   application, and a client that does not list the current redirect URI. No
   restart is needed for the import itself.
5. Add the mailbox with **Authentication: OAuth 2.0**, the Gmail hosts above
   and a credential record such as `google:work` (the form suggests
   `google:<alias>` once the IMAP host is `imap.gmail.com`), then restart
   `mcp approval-ui mail-ui`.
6. Under **Manage mailboxes**, click **Connect Google** next to the mailbox,
   then **Connect with Google** on the page that opens. Sign in with that
   exact Google account; Evergarden refuses to store a token for a different
   address.

Tokens are refreshed before they expire. If Google revokes the grant
(`invalid_grant`, a changed password, an administrator policy), the mailbox
reports that it needs to be connected again; repeat step 6.

## iCloud Mail

1. Create an app-specific password in your Apple Account settings
   (Sign-In and Security, App-Specific Passwords). Two-factor authentication
   must be on.
2. Add the mailbox:

   | Field | Value |
   |---|---|
   | Sign-in address | your iCloud Mail address |
   | IMAP | `imap.mail.me.com`, port `993` |
   | SMTP | `smtp.mail.me.com`, port `587`, STARTTLS |
   | Sent folder | `Sent Messages` |
   | Trash folder | `Deleted Messages` |
   | Archive folder | `Archive` |

3. Store the app-specific password with `set-password`.
4. iCloud has no IMAP MOVE. Either list the alias in
   `EVERGARDEN_UIDPLUS_MOVE_ACCOUNTS` (true moves, Trash possible) or tick "If
   the provider has no native MOVE, allow COPY and keep the source message"
   (copies only, no Trash). See [Servers without IMAP MOVE](#servers-without-imap-move).

## Outlook.com and Microsoft 365

Microsoft mailboxes sign in with OAuth. You register your own app in Microsoft
Entra ID; Evergarden is a public client and never uses a client secret.

### Register the app

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com/) (any
   Microsoft account can register apps), go to **App registrations** and click
   **New registration**.
2. Name: anything. Microsoft shows this name on its sign-in pages; put the same
   text in `EVERGARDEN_MICROSOFT_OAUTH_APP_NAME` (optional, but the sign-in page
   then tells you which app to expect).
3. Supported account types:
   - Outlook.com, Hotmail, Live: a type that includes **personal Microsoft
     accounts**. Use tenant `common` (both kinds of account) or `consumers`
     (personal only).
   - Microsoft 365 work or school account: **this organizational directory
     only**, with your tenant id (from the app's Overview page) as the tenant.
4. Redirect URI (only for the `authorization_code` flow): platform **Mobile and
   desktop applications**, value exactly as `EVERGARDEN_MICROSOFT_OAUTH_REDIRECT_URI`
   in `runtime.env` (setup writes `<origin>/oauth/callback/microsoft`).
5. Under **Authentication**, set **Allow public client flows** to **Yes**. The
   `device_code` flow requires it.
6. Under **API permissions**, add delegated permissions `offline_access`,
   `IMAP.AccessAsUser.All` and `SMTP.Send`. Evergarden requests
   `https://outlook.office.com/IMAP.AccessAsUser.All`,
   `https://outlook.office.com/SMTP.Send` and `offline_access`. In a
   Microsoft 365 tenant an administrator may have to grant consent.
7. In Microsoft 365, SMTP AUTH must be allowed for the mailbox, otherwise
   sending fails while reading works.

Then set in `.local/run/runtime.env`:

```dotenv
EVERGARDEN_MICROSOFT_OAUTH_CLIENT_ID=<Application (client) ID>
EVERGARDEN_MICROSOFT_OAUTH_TENANT=common
EVERGARDEN_MICROSOFT_OAUTH_FLOW=authorization_code
EVERGARDEN_MICROSOFT_OAUTH_APP_NAME=<the app's name>
```

and run `docker compose up -d`. Until the client id is set, the connect page
says "Microsoft sign-in is not configured yet."

### Choose a flow

| `EVERGARDEN_MICROSOFT_OAUTH_FLOW` | How it works | Use it when |
|---|---|---|
| `authorization_code` (default) | The connect page sends you to Microsoft; after sign-in and MFA Microsoft redirects back to `/oauth/callback/microsoft`. PKCE, one-time state, ten-minute expiry. | Your browser reaches Evergarden at the origin in the redirect URI. This is the normal case. |
| `device_code` | The connect page shows a short code; you open Microsoft's device sign-in page, enter the code and sign in. No redirect URI is involved. | You cannot register the redirect URI, or you use the optional [MFA auto-login](advanced/mfa-autologin.md), which needs this flow. |

### Add and connect the mailbox

| Field | Value |
|---|---|
| IMAP | `outlook.office365.com`, port `993` |
| SMTP | `smtp.office365.com`, port `587`, STARTTLS |
| Authentication | OAuth 2.0 |
| Credential record | `microsoft:<alias>`, suggested by the form; for example `microsoft:work` |
| Sent / Trash folder | usually `Sent Items` / `Deleted Items` (check your mailbox) |

After adding it and restarting `mcp approval-ui mail-ui`, click **OAuth / MFA**
next to the mailbox under **Manage mailboxes**, then **Connect with Microsoft**.
Complete sign-in and MFA on Microsoft's page. With `device_code`, enter the
displayed code at **Open Microsoft sign-in** and keep the Evergarden page open
until it reports that the mailbox is authorized.

Access tokens are refreshed 30 minutes before they expire, whenever the sync
or an action uses the mailbox. If Microsoft requires a new interactive sign-in
(error `invalid_grant` or `AADSTS70043`, often an organisation's sign-in
frequency policy), `oauth_status` reports `authorization_required` and you
connect again.

The optional `oauth-maintenance` compose profile refreshes tokens every five
minutes in the background and finishes device-code sign-ins after you close
the page. It only runs when provider writes are enabled
(`EVERGARDEN_SIDE_EFFECTS_ENABLED=true`).

Outlook.com sometimes answers a valid sign-in with "User is authenticated but
not connected". This is a fault on Microsoft's side. Evergarden retries with
fresh connections; a sync that still fails is caught up by the next hourly run.

## Verification codes

**Find verification codes** in the workbench (and the
`find_verification_codes` tool) reads 4-8 digit codes from recent mail (at
most the last 60 minutes) that clearly mention a sign-in or verification. Evergarden
never follows links, fills in or submits codes. Everywhere else, codes in mail
are redacted.
