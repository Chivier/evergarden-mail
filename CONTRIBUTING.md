# Contributing

Thanks for helping. Evergarden handles people's mail, so the bar for safety and
privacy is high; please read this page before opening a pull request.

## Development setup

You need Python 3.12+, [uv](https://docs.astral.sh/uv/), Node.js 22+ (frontend
tests), Docker (Postgres tests and image builds) and, for the hooks,
[gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1.

```bash
uv sync --frozen --all-groups
uv run --frozen pre-commit install --hook-type pre-commit --hook-type pre-push
```

Tests never need a real mailbox: they use fake IMAP, SMTP and OAuth providers
and throwaway keys.

## Tests and checks

```bash
uv run --frozen pytest -q
uv run --frozen ruff check .
uv run --frozen ruff format --check .
node --test tests/frontend/*.test.js
uv run --frozen python deploy/scripts/check_repo_privacy.py
```

The Postgres tests are skipped unless `TEST_DATABASE_URL` points to a
disposable database. One way:

```bash
docker run -d --rm --name evergarden-test-pg -e POSTGRES_PASSWORD=test \
  -p 127.0.0.1:55432:5432 postgres:17.6-bookworm
TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:55432/postgres uv run --frozen pytest -q
docker stop evergarden-test-pg
```

CI also measures coverage (`uv run --frozen coverage run -m pytest` then
`coverage report`); it must stay at or above 85%. CI further builds the images,
renders the Compose files and runs `deploy/scripts/quickstart_smoke.sh`, which
performs the quickstart end to end in a fresh copy. Run that script only in a
throwaway checkout: it creates `.local/` and `.env` and removes its stack and
volume at the end.

## Privacy rules

- Never commit real mail, addresses, host names, domains, IP addresses, tokens
  or keys. Use `example.com`, `.example`, `.test` or `.invalid` and aliases
  such as `work` and `personal`.
- Everything machine-specific lives under the ignored `.local/`.
- `deploy/scripts/check_repo_privacy.py` scans tracked and staged files for
  non-example email addresses, home-directory paths, runtime and credential
  files, and dated notes under `docs/`. It reports only file, line and reason.
  You can add your own literal patterns in `.local/privacy-patterns` (see
  `.privacy-patterns.example`) or a file named by
  `EVERGARDEN_PRIVACY_PATTERNS`.
- gitleaks scans for secrets. The pre-commit hook runs both scanners; the
  pre-push hook also scans the history you are about to push.

## Code rules

The architecture and the rules the code keeps are in
[docs/architecture.md](docs/architecture.md#code-map). In short:

- No path may let an MCP client cause a provider write without an approval, or
  approve anything itself. Tools named `approve`, `delete`, `trash`, `expunge`
  or `move_to_trash` are forbidden.
- **Adding an MCP tool**: add a strict schema to `TOOL_DEFINITIONS`
  (`evergarden/mcp/tool_definitions.py`; reject unknown fields, bound lengths
  and counts), exactly one scope in `TOOL_SCOPES` (`evergarden/auth/policy.py`),
  and a handler in `ToolRuntime`. A write is always a `preview_*`/`prepare_*`
  tool plus an `*_approved` tool going through `ApprovalService`.
  `tests/test_tool_registry.py` checks that the tables cover each other. Update
  [docs/mcp.md](docs/mcp.md).
- **Database**: migrations in `migrations/` are append-only numbered SQL files;
  never edit a released migration.
- **Settings**: a new field in `evergarden/config.py` needs an entry in
  `tools/gen_config_docs.py`; then run `uv run --frozen python tools/gen_config_docs.py`.
  `tests/test_docs.py` fails until the table in `docs/configuration.md` is
  current. Add it to `runtime.env.example` if users are expected to set it.
- **Frontend**: plain HTML, CSS and JavaScript without dependencies, CDNs,
  inline scripts or remote resources (the Content-Security-Policy forbids
  them). Mail HTML is never rendered. Every state-changing request needs the
  CSRF token.
- **Translations**: every UI string goes through the catalogues in
  `apps/shared_static/locales/`. Add each new key to both `en.js` and
  `zh-CN.js` with the same `{placeholders}`; `tests/frontend/i18n.test.js`
  enforces this.
- Never log request bodies, MCP results, mail content, passwords or tokens.

## Documentation

User documentation is in `docs/` (English), with Chinese versions of the
quickstart and user guide in `docs/zh-CN/` and the README in `README.zh-CN.md`.
When you change behaviour, update the docs in the same pull request.
`tests/test_docs.py` checks that relative links and anchors resolve.

`tools/ui-preview/` serves the real UI with made-up data for design work and
screenshots; see its [README](tools/ui-preview/README.md).

## Pull requests

Keep them focused, describe what changed and why, and say how you tested it.
Do not include real mail or secrets in issues, pull requests or logs you paste.
