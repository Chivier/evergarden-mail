# Changelog

All notable changes are listed here. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
contain breaking changes.

## Unreleased

- Dedicated settings page with mailbox editing, add/remove, enable/disable,
  encrypted app-password updates and validated runtime configuration overrides.
  Mailbox/configuration changes require an application restart; secrets and
  deployment identity remain managed on the server.
- Non-expiring API keys with an explicit risk acknowledgement and immediate
  revocation. Existing keys keep their current expiry.
- SOPS materialization now defaults to 15 sign-in failures and 365-day
  compatibility grants, matching setup; no-expiry grants require explicit opt-in.

## 0.1.0 - initial public release

First public release.

- Read-only, incremental IMAP sync of several mailboxes into a local SQLite
  archive with full-text search, threads, encrypted attachments and location
  tracking across folder moves and UIDVALIDITY changes.
- MCP server with 41 scoped tools for reading, searching, drafting, organizing,
  sending and Trash, plus diagnostics; API keys created in the web UI, optional
  OAuth (JWT or introspection) for MCP clients.
- Approval workflow: immutable drafts with a review window, durable human
  approvals with revocation, optional per-kind auto-approval (never for Trash),
  background execution, read-only verification of unknown outcomes and replay
  only of idempotent operations.
- Web workbench and approval pages with batch approval, send review, execution
  log, English and Simplified Chinese interface, dark mode and phone layout.
- Providers: generic IMAP/SMTP with passwords, Gmail (app password or your own
  Google OAuth client), iCloud (UIDPLUS move or copy fallback), Outlook.com and
  Microsoft 365 (your own Entra app; authorization code or device code flow).
- Administrator sign-in for the web surfaces: scrypt password checked off the
  event loop, 7-day sessions by default (at most 30), a `__Host-` cookie on
  HTTPS, sign-out that ends the session on every device, and a sign-in
  throttle per client address (per /64 for IPv6). The gateway resolves that address in one of
  three modes: `direct` (default), `proxy` (trusted `X-Forwarded-For`) or
  `cloudflare` (plus `CF-Connecting-IP` from Cloudflare's published ranges).
- MCP OAuth discovery only when the issuer's tokens can be verified (JWKS or
  introspection); JWKS keys cached with rate-limited refreshes.
- Single-host writer fence: provider writes off by default behind one switch,
  separate Trash switch, writer epoch and leases.
- `./deploy/setup` for a one-command install, Docker Compose stack with a
  one-shot migration service, optional in-stack scheduler or systemd timer,
  reverse-proxy examples.
- Optional components: receive-only Thunderbird bridge, Microsoft MFA
  auto-login, SOPS-managed configuration.
