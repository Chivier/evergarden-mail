# Optional: Thunderbird bridge

Some organisations do not let third-party apps sign in to their mail, but do
allow Thunderbird. The bridge lets a desktop Thunderbird, signed in with its
own OAuth login, upload copies of new Inbox mail to Evergarden. Evergarden
never sees that account's password or tokens and needs no OAuth app of its
own for it.

A bridged mailbox is **receive-only**: you can read and search its mail in
Evergarden and through MCP, but every write (send, archive, move, mark, Trash)
for it is refused. Act on that mail in Thunderbird.

## Requirements

- Evergarden reachable over HTTPS (a public origin; see
  [operations.md](../operations.md#reverse-proxy-and-https)). The add-on is
  built for that origin and refuses plain HTTP.
- Thunderbird 128 or newer on a desktop that stays running.
- Your reverse proxy allows request bodies of 24 MiB on `/bridge/`.

## Configure

1. Add the mailbox to the inventory (under **Manage mailboxes** or in
   `mail_accounts.json`) with its real address and alias, for example `work`.
   Leave it disabled if Evergarden should not sign in to it itself; it can also
   be enabled for native sync, and it stays receive-only either way.
2. In `.local/run/runtime.env`:

   ```dotenv
   EVERGARDEN_THUNDERBIRD_BRIDGE_ACCOUNTS=work
   ```

3. `docker compose up -d`.

**Company mail notifications** now appears in the workbench sidebar.

## Pair Thunderbird

1. In Thunderbird, add the account and sign in with its OAuth login. Check that
   Thunderbird receives mail.
2. In the workbench open **Company mail notifications**, click **Download the
   Thunderbird add-on**, and install it in Thunderbird from Add-ons, **Install
   Add-on From File**.
3. Click **Download pairing file** and import it in the add-on's settings.
   The file holds a token that can only upload mail for this mailbox; keep it
   private. Downloading a new pairing file invalidates the previous one. The
   token is valid for one year.
4. Keep Thunderbird running. New Inbox mail is uploaded and appears in the
   archive and in the notification list. The workbench checks for
   notifications every 30 seconds and can show desktop alerts (**Enable desktop
   alerts**) while it is open.

The status line shows whether the bridge is online and how many messages wait
for upload. Without a heartbeat for three minutes it shows as offline; the
add-on's settings show the reason for a failure and can retry.

## What gets uploaded

- Only the Inbox of the paired account. The first run uploads the last 7 days;
  older mail is not uploaded.
- At start and every minute the add-on rescans the last 7 days (by Date
  header) to catch mail that arrived while it was not running. Mail delivered
  while Thunderbird was offline for more than 7 days is not caught up.
- At most 16 MiB per message; larger messages stay in Thunderbird and are
  reported as too large. The local upload queue holds at most 100 messages.
- The add-on deletes a queued copy only after Evergarden confirms it. Evergarden
  deduplicates by message identity, so a repeated upload is harmless.

The add-on asks for permission to read accounts and messages, use timers and
local storage, and connect to your Evergarden origin only.

## Disconnect

**Disconnect bridge** revokes the upload token at once. Archived mail and
notifications stay. Removing the alias from `EVERGARDEN_THUNDERBIRD_BRIDGE_ACCOUNTS`
disables the bridge; nothing at the provider changes.
