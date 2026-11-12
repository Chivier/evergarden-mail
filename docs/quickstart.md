# Quickstart

This guide installs Evergarden on one machine, connects one mailbox and one MCP
client, and ends with a first approved action. It takes about fifteen minutes,
most of it the first image build.

Everything runs on `127.0.0.1`. To reach the install from other machines, finish
this guide first, then follow
[operations.md](operations.md#reverse-proxy-and-https).

## Requirements

- A Linux host with Docker Engine and Docker Compose v2.24 or newer
  (`docker compose version`).
- Python 3.10 or newer for the setup script (standard library only).
- Git.
- Free host ports 8788, 8420 and 8421 on `127.0.0.1` (all three can be changed).
- A mailbox that accepts IMAP and SMTP with a password or an app password.
  Gmail and iCloud work this way; Microsoft accounts need OAuth, see
  [providers.md](providers.md).

## 1. Clone and run setup

```bash
git clone https://github.com/Chivier/evergarden-mail.git evergarden
cd evergarden
./deploy/setup
```

In a terminal, setup asks two questions. Press Enter to accept the defaults
(origin `http://127.0.0.1:8788`, username `admin`).

Setup creates `.local/` (private keys, the encrypted credential store, the
archive directory), `.local/run/runtime.env` and `.env`. It prints a list of
created files, then:

```text
Administrator login (shown only this once; store it in a password manager):
  username: admin
  password: <generated password>
```

Save the password now. It is not stored in plain text anywhere. If you lose
it, see [operations.md](operations.md#reset-the-administrator-password).

Setup also prints the next steps and a reminder that provider writes are off.
Running it again is safe: it never overwrites an existing file.

To use other host ports, pass them on the first run, for example
`./deploy/setup --http-port 38788 --mcp-port 38420 --approval-port 38421`.
They end up as `EVERGARDEN_HTTP_PORT`, `EVERGARDEN_MCP_PORT` and
`EVERGARDEN_APPROVAL_PORT` in `.env`. Replace 8788, 8420 and 8421 below with
your ports.

## 2. Start the stack

```bash
docker compose up -d --build
docker compose ps
```

The first build takes a few minutes. Wait until `postgres`, `mcp`,
`approval-ui`, `mail-ui`, `gateway` and `scheduler` are `healthy` and `migrate`
has `Exited (0)`. The `migrate` service creates the database schema and exits;
it runs on every `up`.

## 3. Sign in

Open <http://127.0.0.1:8788> and sign in with `admin` and the printed password.
You land on the mail workbench, which is empty until you add a mailbox. The
EN / 中文 switch at the bottom of the sidebar changes the interface language.

## 4. Add a mailbox

1. Click **+** next to **Mailboxes** in the sidebar ("Manage mailboxes").
2. Expand **Add a mailbox** and fill in the form. For a password mailbox:

   | Field | Example |
   |---|---|
   | Alias | `personal` (lowercase; used in commands and tool calls) |
   | Sign-in address | `you@example.com` |
   | Authentication | **App password** |
   | Credential record | `password:personal`, filled in from the alias and authentication. You can change it; any stable id works. |
   | IMAP host / port | `imap.example.com` / `993` |
   | SMTP host / port / security | `smtp.example.com` / `587` / **STARTTLS** (or `465` / **Implicit TLS**) |
   | Archive, Sent, Trash folder | your provider's folder names |
   | Folders to sync | `INBOX, Archive` |
   | Allowed move destinations | must include the Archive folder; never Trash or Junk |

   [providers.md](providers.md) lists the values for Gmail, iCloud and others.
3. Click **Save private configuration**. The notice reads "Mailbox written to
   the private configuration. Finish credentials or OAuth, then restart the
   service."

The form never accepts a password. Store it from the command line:

```bash
docker compose exec approval-ui evergarden-provider-credential set-password --account personal
```

Type the app password at the `App password:` prompt (nothing is echoed). The
command answers `{"account": "personal", "credential_version": 1, "stored": true}`.
To pipe it from a password manager instead, add `-T` after `exec` and pass the
password on standard input.

Then restart the services that read the mailbox list. This is needed after
every mailbox change:

```bash
docker compose restart mcp approval-ui mail-ui
```

## 5. First sync

Reload the workbench and click **Sync mail**. A sync is read-only: it never
changes anything at the provider. When it works, the button area shows
"Synced 1 mailboxes" and your mail appears under **Today** and **All mail**.

When it fails, it shows "Sync did not finish" and a notice that lists each
mailbox that did not sync with a short reason. A wrong IMAP host, for example,
looks like this:

```text
These mailboxes did not sync:
• personal cannot resolve the server name. Check the IMAP host.
  ▸ Technical detail
```

The other reasons are "the server refused the connection" (wrong host or
port), "authentication failed" (run the `set-password` command again, or
reconnect OAuth), "the server did not answer in time" and a generic "the sync
failed". **Technical detail** shows the provider's own error, for example
`gaierror: [Errno -2] Name or service not known`. The notice stays until you
close it. The web UI can add and disable mailboxes but
not edit them, so fix a wrong host or folder in
`.local/run/mail-config/mail_accounts.json` with a text editor. Then restart as
above and sync again.

After this the `scheduler` service syncs every mailbox once an hour, at minute
03.

## 6. Connect an MCP agent

1. Click **Connect an MCP agent** in the sidebar.
2. Enter a **Name** (for example `laptop`), pick a **Permission level**
   (**Read only**, **Read + drafts** or **Full**) and **Valid for**, then click
   **Create API key**.
3. The key is shown once. The client snippets below it now contain the key and
   your MCP URL; copy them from the dialog.

For Claude Code the dialog generates:

```bash
umask 077
printf '%s' '<your API key>' > ~/.evergarden-mcp.token

TOKEN="$(tr -d '\n' < ~/.evergarden-mcp.token)"
claude mcp remove evergarden-mail -s user 2>/dev/null || true
claude mcp add --transport http evergarden-mail http://127.0.0.1:8788/mcp \
  --scope user \
  --header "Authorization: Bearer ${TOKEN}"
unset TOKEN

claude mcp list
```

For Codex:

```bash
umask 077
printf 'EVERGARDEN_MCP_TOKEN=%s\n' '<your API key>' >> ~/.codex/.env
chmod 600 ~/.codex/.env

codex mcp remove evergarden-mail 2>/dev/null || true
codex mcp add evergarden-mail \
  --url http://127.0.0.1:8788/mcp \
  --bearer-token-env-var EVERGARDEN_MCP_TOKEN

codex mcp list
```

`claude mcp list` should report the server as connected; `codex mcp list`
should show it with a bearer token. (The Codex snippet appends to
`~/.codex/.env`; create `~/.codex` first if Codex has never run.) Other clients: see [mcp.md](mcp.md).

To check the key without a client (this reads the token file from the Claude
Code snippet; if you only use Codex, save the key the same way first with
`umask 077; printf '%s' '<your API key>' > ~/.evergarden-mcp.token`):

```bash
TOKEN="$(tr -d '\n' < ~/.evergarden-mcp.token)"
curl -sS -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  http://127.0.0.1:8788/mcp
```

The answer is a JSON-RPC result listing the tools your key's scopes allow. A
request without the header gets HTTP 401.

Your agent can now read, search and draft. Every send, move, mark or Trash it
prepares waits for you on the approval page.

## 7. Enable provider writes

A new install is read-only: you can approve actions, but nothing is sent or
moved at the provider. When you are ready, edit `.local/run/runtime.env`:

```dotenv
EVERGARDEN_SIDE_EFFECTS_ENABLED=true
# Recommended: run your approvals in the background, even when no client is connected.
EVERGARDEN_APPROVAL_DISPATCH_ENABLED=true
```

and apply it:

```bash
docker compose up -d
curl -s http://127.0.0.1:8420/healthz
```

The health answer now contains `"mode":"production"`. Every write still needs
an approval. Moving mail to Trash has its own switch,
`EVERGARDEN_TRASH_ACTIONS_ENABLED`, which you can leave off.

## 8. Approve a first action

1. In the workbench open a message and click **Mark**, then **Mark as read**.
   The "Check the immutable operation" dialog shows the exact change.
2. Click **Open the approval page**. It opens in a new tab and shows the
   message and the operation. Click **Approve**.
3. With the background dispatcher on, the page reports "Approved and queued.
   The server runs it automatically, even if you close this page." The
   **Execution log** tab shows the item move from Running to **Succeeded**.

   Without the dispatcher, go back to the workbench dialog, click **Check
   approval status**, then **Run approved operation**.

An agent works the same way: it prepares the action, you approve it on the
approval page. See the [user guide](user-guide.md) for the approval queue,
batch approval and revocation.

## Stop, upgrade, back up

```bash
docker compose stop                # stop, keep everything
docker compose up -d               # start again
docker compose down                # remove containers; data stays in .local/ and the Postgres volume
```

`docker compose down -v` also deletes the Postgres volume, and with it every
draft, approval and audit record. Do not use `-v` on an install you want to
keep.

Upgrade:

```bash
git pull
docker compose up -d --build
```

The `migrate` service applies new database migrations automatically. Compare
`runtime.env.example` with your `.local/run/runtime.env` for new settings.

Back up the Postgres database, `.local/` and `.env`; see
[operations.md](operations.md#back-up-and-restore). `.local/run/credential_store_key`
and `EVERGARDEN_HOST_ID` together decrypt your stored mailbox credentials;
without them a restore cannot read the passwords and tokens.
