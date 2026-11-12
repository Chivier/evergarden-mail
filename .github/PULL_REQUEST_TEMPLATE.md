## What and why

## How it was tested

- [ ] `uv run --frozen pytest -q` (with `TEST_DATABASE_URL` for the Postgres tests)
- [ ] `uv run --frozen ruff check .` and `uv run --frozen ruff format --check .`
- [ ] `node --test tests/frontend/*.test.js` (if the UI changed)
- [ ] `uv run --frozen python deploy/scripts/check_repo_privacy.py`

## Checklist

- [ ] No real mail content, addresses, host names, tokens or keys in code,
      tests, docs or commit messages (use `example.com` / `.test` / `.invalid`).
- [ ] Every new UI string is in both `apps/shared_static/locales/en.js` and
      `zh-CN.js`.
- [ ] New or changed settings are documented (`uv run python tools/gen_config_docs.py`).
- [ ] No new path lets an agent cause a provider write without an approval.
