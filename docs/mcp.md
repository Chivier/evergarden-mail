# MCP server

Evergarden's MCP endpoint is `<origin>/mcp`, for example
`http://127.0.0.1:8788/mcp` on a local install (the gateway). The MCP service
also listens directly on `http://127.0.0.1:8420/mcp`. It speaks JSON-RPC over
HTTP and implements `initialize`, `ping`, `tools/list` and `tools/call`.

Every request needs `Authorization: Bearer <token>`. A request without one gets
HTTP 401 with a `WWW-Authenticate: Bearer` challenge. Only when OAuth
verification is configured (`EVERGARDEN_OAUTH_JWKS_URL` or introspection, see
[advanced/authelia-oauth.md](advanced/authelia-oauth.md)) does the challenge
also name the protected-resource metadata at
`<origin>/.well-known/oauth-protected-resource/mcp`; otherwise clients use API
keys.

## Credentials

| Kind | Issued by | Use |
|---|---|---|
| API key | You, in the web UI ("Connect an MCP agent") | Personal agents such as Claude Code and Codex. The normal choice. |
| OAuth access token | An external OAuth authorization server you run | Clients that need a standard OAuth login. Optional; see [advanced/authelia-oauth.md](advanced/authelia-oauth.md). |
| Static compatibility token | `.local/run/compatibility_tokens.json` | Internal: setup registers the web UI's own token here. |

The administrator login of the web UI is separate: a browser session cookie is
never accepted at `/mcp`, and an MCP token never opens a browser session.

### API keys

Open **Connect an MCP agent** in the workbench sidebar. The dialog shows the MCP
resource URL and the available scopes, lists existing keys and creates new
ones:

- **Name**: becomes the client id `ui-<name>`.
- **Permission level**: **Read only** (`mail:metadata mail:read
  mail:attachments mail:verification`), **Read + drafts** (adds `mail:draft
  mail:sync mail:settings`), **Full** (every scope) or **Custom** (**Choose
  scopes one by one**).
- **Valid for**: 30, 90 or 365 days.

**Create API key** shows the key once and fills it into the client snippets
below. Only its SHA-256 hash is stored. A lost key cannot be recovered; revoke
it and create a new one. Creating and revoking take effect immediately, without
a restart. At most 32 keys can exist at a time.

A key is bound to `EVERGARDEN_MCP_RESOURCE`. If you change the public origin,
create new keys.

## Client setup

The dialog generates these snippets with your URL and key filled in. Keep the
key in a mode-0600 file and never paste it into a chat, issue or repository.

### Claude Code

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

`--scope user` makes the server available in every project. `claude mcp list`
should report it as connected. Avoid `claude mcp get evergarden-mail`: some
versions print the full bearer token.

### Codex

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

If `EVERGARDEN_MCP_TOKEN` is already in `~/.codex/.env`, replace that line
instead of appending. Create `~/.codex` first if it does not exist. The equivalent `~/.codex/config.toml` entry is:

```toml
[mcp_servers.evergarden-mail]
url = "http://127.0.0.1:8788/mcp"
bearer_token_env_var = "EVERGARDEN_MCP_TOKEN"
startup_timeout_sec = 30
tool_timeout_sec = 120
default_tools_approval_mode = "writes"
```

Do not also set `auth = "oauth"` or a static `Authorization` header.
`codex mcp list` should show a bearer token, not "Not logged in".

### Other clients

For clients that read an `mcpServers` file (keep the file mode 0600):

```json
{
  "mcpServers": {
    "evergarden-mail": {
      "type": "http",
      "url": "http://127.0.0.1:8788/mcp",
      "headers": {
        "Authorization": "Bearer <your API key>"
      }
    }
  }
}
```

### Check with curl

```bash
TOKEN="$(tr -d '\n' < ~/.evergarden-mcp.token)"
curl -sS -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  http://127.0.0.1:8788/mcp
```

### Troubleshooting

| Symptom | Cause |
|---|---|
| HTTP 401, `invalid_token` | The key is wrong, expired or revoked, or was issued for another `EVERGARDEN_MCP_RESOURCE`. Create a new one. |
| HTTP 403, `insufficient_scope` | The key lacks a scope the tool needs; the `WWW-Authenticate` header names it. Create a key with more scopes. |
| A tool is missing from `tools/list` | `tools/list` only shows tools your key's scopes allow. |
| Codex says "Not logged in" | It is still configured for OAuth. Use `bearer_token_env_var` as above. |
| Both OAuth and a header are configured | Keep only one; a rejected bearer token does not fall back to OAuth. |

## Scopes and tools

| Scope | Tools | What they do |
|---|---|---|
| `mail:metadata` | `service_info`, `health_status` | Content-free description of the service, its write switches and auto-approval policy. |
| `mail:metadata` | `list_accounts`, `list_folders`, `sync_status`, `mailbox_stats` | Mailboxes with their folders and allowed actions, folder counts, sync watermarks, archive counts. Never credentials. |
| `mail:metadata` | `list_recent`, `count_mail` | Message metadata without bodies (filters, pagination, location status); exact counts. |
| `mail:metadata` | `list_sent_metadata` | Live Sent-folder headers of up to the last 31 days; no bodies, no archive or provider change. |
| `mail:metadata` | `oauth_status` | Whether each OAuth mailbox has a usable token; never the token. |
| `mail:metadata` | `diagnose_message`, `submit_mail_feedback`, `get_mail_feedback`, `list_mail_feedback` | Content-free location evidence for one message, and feedback records for location problems. Feedback never approves or executes anything. |
| `mail:sync` | `sync_mail` | Bounded read-only sync. |
| `mail:read` | `search_mail`, `get_message`, `get_thread` | Full-text search with redacted snippets; one message or a thread as sanitized plain text. HTML is never returned. |
| `mail:attachments` | `list_attachments`, `download_attachment` | Attachment metadata; one allowed attachment as bounded base64. |
| `mail:attachments` | `stage_attachment` | Check and encrypt a local file for an outgoing message. |
| `mail:draft` | `prepare_send`, `get_draft_status` | Prepare a new message; read a draft's approval and execution state (only the client that prepared it may). |
| `mail:read` + `mail:draft` | `prepare_reply`, `prepare_forward` | Prepare a reply or forward of an archived message. |
| `mail:send-approved` | `send_approved` | Send a prepared message with its approval. |
| `mail:organize` | `preview_archive`, `archive_approved` | Archive to the mailbox's Archive folder. |
| `mail:organize` | `preview_move`, `move_approved` | Move to an allowed folder of the same mailbox. |
| `mail:organize` | `preview_move_unrelated`, `move_unrelated_approved` | Shortcut for a move to the folder `Unrelated`; it must be in the mailbox's allowed move destinations. |
| `mail:organize` | `preview_mark`, `mark_approved` | Mark read, unread, flagged or unflagged. |
| `mail:delete` | `preview_trash`, `trash_approved` | Move to the mailbox's Trash folder. Always needs a human approval. |
| `mail:settings` | `get_mail_preferences`, `edit_global_notes`, `edit_mailbox_preferences` | Read and edit your encrypted global notes and per-mailbox descriptions. |
| `mail:verification` | `find_verification_codes` | Codes from the last 1-60 minutes of mail with a clear sign-in context. Never submitted. |
| `mail:operations` | `mail_operations_status` | Content-free job, action-ledger and writer status. Only **Full** or **Custom** keys get it. |

The live schema of every tool comes from `tools/list`; the definitions are in
[`evergarden/mcp/tool_definitions.py`](../evergarden/mcp/tool_definitions.py).
Schemas reject unknown fields, wrong types and out-of-range values.

There is no tool to approve, to delete permanently, to expunge or to send raw
provider commands.

## How writes work for an agent

Every write is two steps: a `prepare_*`/`preview_*` tool creates an immutable
draft, and the change happens only after an approval. The prepare result
contains:

| Field | Meaning |
|---|---|
| `draft_id`, `payload_hash`, `review_packet` | The draft. The exact packet is what will be executed. |
| `expires_at` | End of the review window (`EVERGARDEN_APPROVAL_DRAFT_LIFETIME_HOURS`, default 6 h). |
| `requires_human_approval` | `true`: a person must approve it in the web UI. `false`: the kind is in `EVERGARDEN_AUTO_APPROVE` and the result already carries `approval_id`. |
| `approval_path` | Relative URL of the approval page; prefix it with the web origin and give it to the user. |
| `execution_owner` | `server`: the background dispatcher runs the approved draft; poll `get_draft_status`. `client`: call the matching `*_approved` tool once the draft is approved. |

To execute as the client, call the `*_approved` tool with `approval_id`,
`draft_id` and the unchanged `review_packet` as `payload`. Any change is
rejected. For a human-approved draft, `get_draft_status` returns the approval id
once a person has approved it.

Results and errors an agent should handle:

| Code | Meaning |
|---|---|
| `PROVIDER_NOT_ATTEMPTED` | The mailbox could not be reached before any change was made (connection, sign-in, token refresh). Nothing changed; the approval is still valid. Try again later. |
| `WRITER_LEASE_UNAVAILABLE` | The approval is already running, or writes are not enabled on this host. Check `get_draft_status` before retrying. |
| `APPROVAL_CLOSED_BEFORE_PROVIDER_REACHED` | The approval was revoked or lapsed before the mailbox was reached. Prepare a new draft. |
| `PROVIDER_NATIVE_MOVE_UNAVAILABLE` | The mailbox supports neither IMAP MOVE nor a configured UIDPLUS move. |
| `strategy: "uidplus_expunge"` | The move used UIDPLUS: the copy was verified, then only the original was expunged. |
| `mail_sync_incomplete` | `sync_mail` failed for some mailboxes. `failed_accounts` names them with an error class; `partial_results` shows the rest. Other mailboxes were still synced. |

When the network fails after a provider accepted a command, the outcome is
unknown. Evergarden then checks the mailbox read-only before doing anything
else and never resends mail; see [architecture.md](architecture.md#approval-lifecycle).
Do not prepare a changed draft "to try again" while an earlier one is still
being verified.

`oauth_status` checks only the local credential store: `ready` (token valid),
`refresh_required`, or `authorization_required` (connect the mailbox again in
the web UI).

## Example calls

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "list_recent",
            "arguments": {"account": "all", "since": "2026-01-05T00:00:00Z", "limit": 50}}}
```

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
 "params": {"name": "preview_archive",
            "arguments": {"account": "work", "stable_message_id": "<id from list_recent>",
                          "source_folder": "INBOX"}}}
```
