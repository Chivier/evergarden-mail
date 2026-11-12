#!/usr/bin/env bash
# End-to-end check of the documented quickstart, run from a fresh checkout:
#   ./deploy/setup --non-interactive; docker compose up -d --build; sign in over
#   loopback HTTP; create an MCP API key in the UI; call MCP through the gateway.
# The stack and its volume are removed again on exit (docker compose down -v).
#
# Run it only in a throwaway copy: it creates .local/ and .env in the current
# directory and refuses to start when either already exists.
#
# Environment (all optional):
#   SMOKE_PROJECT        compose project name      (default evergarden-smoke)
#   SMOKE_HTTP_PORT      gateway host port         (default 8788)
#   SMOKE_MCP_PORT       MCP host port             (default 8420)
#   SMOKE_APPROVAL_PORT  approval UI host port     (default 8421)
#   SMOKE_IMAGE_PREFIX   image name prefix         (default <project>)
#   SMOKE_REMOVE_IMAGES  1 removes the built images on exit
#   SMOKE_TIMEOUT        seconds to wait for health (default 300)
set -euo pipefail

project="${SMOKE_PROJECT:-evergarden-smoke}"
http_port="${SMOKE_HTTP_PORT:-8788}"
mcp_port="${SMOKE_MCP_PORT:-8420}"
approval_port="${SMOKE_APPROVAL_PORT:-8421}"
prefix="${SMOKE_IMAGE_PREFIX:-$project}"
timeout="${SMOKE_TIMEOUT:-300}"
origin="http://127.0.0.1:$http_port"
work="$(mktemp -d)"

if [[ ! -f docker-compose.yaml || ! -x deploy/setup ]]; then
  echo "run from the repository root" >&2
  exit 2
fi
if [[ -e .local || -e .env ]]; then
  echo ".local or .env already exists; run the smoke test in a fresh copy" >&2
  exit 2
fi

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    docker compose ps -a || true
    docker compose logs --no-color --tail 80 || true
  fi
  docker compose --profile '*' down -v --remove-orphans || true
  if [[ "${SMOKE_REMOVE_IMAGES:-0}" == "1" ]]; then
    docker image rm "$prefix:app" "$prefix:autologin" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "setup"
./deploy/setup --non-interactive --project "$project" --http-port "$http_port" \
  --mcp-port "$mcp_port" --approval-port "$approval_port" >"$work/setup.out"
sed '/password:/d' "$work/setup.out"
password="$(sed -n 's/^  password: //p' "$work/setup.out")"
[[ -n "$password" ]] || { echo "setup printed no administrator password" >&2; exit 1; }
grep -qx 'EVERGARDEN_ADMIN_SECURE_COOKIES=false' .local/run/runtime.env
grep -qx 'EVERGARDEN_SIDE_EFFECTS_ENABLED=false' .local/run/runtime.env
sed -i "s|^EVERGARDEN_IMAGE=.*|EVERGARDEN_IMAGE=$prefix:app|; s|^EVERGARDEN_AUTOLOGIN_IMAGE=.*|EVERGARDEN_AUTOLOGIN_IMAGE=$prefix:autologin|" .env

step "setup is idempotent"
before="$(sha256sum .local/run/admin_credentials.json .local/run/credential_store_key .local/run/runtime.env .env)"
./deploy/setup --non-interactive --project "$project" >"$work/setup2.out"
if grep -q 'password:' "$work/setup2.out"; then
  echo "second setup run printed a password" >&2
  exit 1
fi
[[ "$before" == "$(sha256sum .local/run/admin_credentials.json .local/run/credential_store_key .local/run/runtime.env .env)" ]]

step "docker compose up -d --build"
docker compose up -d --build

step "wait for health"
deadline=$((SECONDS + timeout))
until curl -fsS -o /dev/null "$origin/gateway-healthz" 2>/dev/null \
  && curl -fsS -o /dev/null "http://127.0.0.1:$mcp_port/healthz" 2>/dev/null; do
  if ((SECONDS > deadline)); then
    echo "stack did not become healthy within ${timeout}s" >&2
    exit 1
  fi
  sleep 3
done

step "migrations ran once and exited 0"
[[ "$(docker compose ps -a migrate --format '{{.ExitCode}}')" == "0" ]]
docker compose logs --no-color migrate | grep -q '"applied": \["001_initial.sql"'

step "only database services can reach postgres"
probe='import socket; socket.create_connection(("postgres", 5432), timeout=3).close()'
docker compose exec -T mcp python -c "$probe"
docker compose exec -T approval-ui python -c "$probe"
if docker compose exec -T mail-ui python -c "$probe" >/dev/null 2>&1; then
  echo "mail-ui can open a connection to postgres:5432" >&2
  exit 1
fi
docker compose exec -T gateway sh -c 'command -v nc' >/dev/null
if docker compose exec -T gateway nc -z -w 3 postgres 5432 >/dev/null 2>&1; then
  echo "gateway can open a connection to postgres:5432" >&2
  exit 1
fi

step "login page and loopback login"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$origin/login")" == "200" ]]
python3 -c 'import json,sys; print(json.dumps({"username": "admin", "password": sys.argv[1]}))' \
  "$password" >"$work/login.json"
[[ "$(curl -sS -c "$work/cookies" -o /dev/null -w '%{http_code}' \
  -H 'content-type: application/json' --data @"$work/login.json" "$origin/api/login")" == "200" ]]
grep -q evergarden_admin_session "$work/cookies"
curl -fsS -b "$work/cookies" "$origin/api/session" >"$work/session.json"
csrf="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["csrf"])' "$work/session.json")"

step "create an MCP API key in the UI and call MCP through the gateway"
revision="$(curl -fsS -b "$work/cookies" "$origin/api/admin/api-keys" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["revision"])')"
python3 -c 'import json,sys; print(json.dumps({"expected_revision": sys.argv[1], "label": "smoke", "scopes": ["mail:metadata"], "ttl_days": 1}))' \
  "$revision" >"$work/key-request.json"
curl -fsS -b "$work/cookies" -H "x-csrf-token: $csrf" -H 'content-type: application/json' \
  --data @"$work/key-request.json" "$origin/api/admin/api-keys" >"$work/key.json"
python3 -c 'import json,sys; print("Authorization: Bearer " + json.load(open(sys.argv[1]))["token"])' \
  "$work/key.json" >"$work/auth-header"
for endpoint in "$origin/mcp" "http://127.0.0.1:$mcp_port/mcp"; do
  curl -fsS -H @"$work/auth-header" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_accounts","arguments":{}}}' \
    "$endpoint" | grep -q '"result"'
done
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$origin/mcp")" == "401" ]]

step "API-key-only discovery advertises no authorization server"
curl -fsS "$origin/.well-known/oauth-protected-resource/mcp" >"$work/metadata.json"
python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); assert "authorization_servers" not in m, m' \
  "$work/metadata.json"

step "approval routes reach the approval UI through the gateway"
curl -fsS -b "$work/cookies" "$origin/session" | grep -q '"surface":"approval"'
python3 -c 'import json; print(json.dumps({"items": [{"draft_id": "smoke", "payload_hash": "smoke"}]}))' \
  >"$work/revoke.json"
[[ "$(curl -sS -b "$work/cookies" -o /dev/null -w '%{http_code}' -H "x-csrf-token: $csrf" \
  -H 'content-type: application/json' --data @"$work/revoke.json" "$origin/approvals/revoke")" == "200" ]]

step "logout revokes the session on both browser surfaces"
cp "$work/cookies" "$work/copied-cookies"
[[ "$(curl -sS -b "$work/cookies" -o /dev/null -w '%{http_code}' -X POST \
  -H "x-csrf-token: $csrf" "$origin/api/logout")" == "200" ]]
[[ "$(curl -sS -b "$work/copied-cookies" -o /dev/null -w '%{http_code}' "$origin/api/session")" == "401" ]]
[[ "$(curl -sS -b "$work/copied-cookies" -o /dev/null -w '%{http_code}' "$origin/session")" == "401" ]]

step "MCP health reports a read-only install"
curl -fsS "http://127.0.0.1:$mcp_port/healthz" >"$work/health.json"
grep -q '"side_effects_enabled":false' "$work/health.json"

step "the default host id is neutral"
grep -qx 'EVERGARDEN_HOST_ID=default' .local/run/runtime.env
machine="$(hostname -s 2>/dev/null || true)"
if [[ ${#machine} -ge 4 ]] && grep -qiF "$machine" "$work/health.json"; then
  echo "health output contains the machine's host name" >&2
  exit 1
fi

step "gateway runs the default direct client-address mode"
docker compose logs --no-color gateway | grep -q 'client address mode direct'
[[ "$(docker compose exec -T gateway cat /tmp/evergarden-gateway/real-ip.conf)" == \
  "include /etc/nginx/real-ip/direct.conf;" ]]

step "forged X-Forwarded-For cannot rotate the login throttle key"
python3 -c 'import json; print(json.dumps({"username": "admin", "password": "wrong-password-0"}))' \
  >"$work/bad-login.json"
max_failures="$(sed -n 's/^EVERGARDEN_ADMIN_LOGIN_MAX_FAILURES=//p' .local/run/runtime.env)"
for attempt in $(seq 1 "${max_failures:-15}"); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
    -H "X-Forwarded-For: 198.51.100.$attempt" -H "CF-Connecting-IP: 198.51.100.$attempt" \
    --data @"$work/bad-login.json" "$origin/api/login")"
  [[ "$code" == "401" ]] || { echo "failed login $attempt returned $code" >&2; exit 1; }
done
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -H 'X-Forwarded-For: 203.0.113.250' --data @"$work/bad-login.json" "$origin/api/login")" == "429" ]]

printf '\nquickstart smoke passed\n'
