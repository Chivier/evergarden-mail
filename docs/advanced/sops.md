# Advanced: configuration in SOPS

`./deploy/setup` is the normal way to create `.local/run/`. As an alternative,
you can keep the deployment's configuration and secrets in two
[SOPS](https://github.com/getsops/sops) documents encrypted with
[age](https://github.com/FiloSottile/age), and render `.local/run/` from them
with `deploy/scripts/materialize_secrets.py`. This suits people who already
manage secrets with SOPS, want the encrypted documents in a private backup,
or rebuild hosts often.

You need `sops`, `age` and `uv` (`uv sync` in the clone). The encrypted
documents and the age key stay out of Git: `.local/` is ignored.

## Documents

| Document | Contents |
|---|---|
| `.local/config/common.sops.yaml` | MCP resource, OAuth issuer, Microsoft client id, tenant and redirect URI, the mailbox inventory (`accounts`), and the scopes of each static MCP client (`clients`). |
| `.local/config/host.sops.yaml` | `host_id`, the writer settings, the credential store key, the Postgres password and one static token per client in `clients`. |

[`config/sops.example.yaml`](../../config/sops.example.yaml) is an example of
the creation rules (`.sops.yaml`).

## Set up

```bash
install -d -m 700 .local/config
age-keygen -o .local/config/age.key        # or keep the key outside the clone
# write .local/config/.sops.yaml from config/sops.example.yaml with your age recipient
uv run python deploy/scripts/bootstrap_sops.py --config-dir .local/config --host-id <stable-id>
sops .local/config/common.sops.yaml        # add your mailboxes under accounts, set client ids
```

`bootstrap_sops.py` generates both documents with fresh keys and tokens and
refuses to overwrite an existing one.

Create the administrator login (prompts for a password, or use
`--generate-password --recovery-output <file>`):

```bash
uv run python deploy/scripts/manage_admin_credentials.py --root . --username admin
```

Render the runtime files:

```bash
uv run python deploy/scripts/materialize_secrets.py \
  --root . \
  --age-key .local/config/age.key \
  --public-origin https://mail.example.com \
  --enable-human-web --enable-account-admin --enable-api-keys
```

It decrypts in memory and writes `.local/run/runtime.env`, `credential_store_key`,
`postgres_password`, `pgpass`, `compatibility_tokens.json`,
`mail_ui_mcp_token`, `mail-config/mail_accounts.json` and one plaintext token
per static client under `.local/run/smoke/`, all mode 0600 (the Postgres
password 0640). It prints no secret. Settings you added to `runtime.env` by
hand are kept. It refuses to change the host id, writer or write switches
already present in `runtime.env` unless you pass `--allow-writer-control-change`.

Static client tokens are registered for 45 days; run the materializer again to
extend them. Finally create `.env` from `.env.example` (set `EVERGARDEN_UID`
and `EVERGARDEN_GID` to `id -u` / `id -g`) and run `docker compose up -d --build`.

## Rotation

- **age recipient**: add the new recipient to `.sops.yaml`, run
  `sops updatekeys` on both documents, check that both identities decrypt, then
  remove the old recipient.
- **Static client token**: change it in `host.sops.yaml`, run the materializer,
  restart `mcp` and `mail-ui`, update the client.
- **Credential store key**: do not just replace it; every stored credential is
  encrypted with it. Re-store the credentials (passwords, OAuth connections)
  after a key change.

Mailbox passwords and OAuth tokens are never in SOPS. They enter the encrypted
credential store through `set-password` and the OAuth pages, as in the normal
setup.
