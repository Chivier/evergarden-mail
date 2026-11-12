#!/usr/bin/env bash
# Behaviour test of the gateway's real-client-address modes
# (EVERGARDEN_GATEWAY_REAL_IP, deploy/nginx/real-ip/).
#
# It starts the gateway image from docker-compose.yaml with the repository's
# gateway configuration, the same entrypoint, read-only root and tmpfs mounts,
# once per mode, on a throwaway internal Docker network. A stand-in for the
# mail UI echoes the X-Forwarded-For it receives, and client containers send
# requests with forged or proxied headers. Nothing is published on the host.
# Everything it creates is removed on exit.
#
# Environment (optional):
#   REALIP_SMOKE_PREFIX  name prefix of the network and containers
#                        (default evergarden-realip-smoke)
set -euo pipefail

prefix="${REALIP_SMOKE_PREFIX:-evergarden-realip-smoke}"
net="$prefix-net"
root="$(pwd)"

if [[ ! -f docker-compose.yaml || ! -f deploy/nginx/real-ip/entrypoint.sh ]]; then
  echo "run from the repository root" >&2
  exit 2
fi
image="$(sed -n 's/^ *image: \(nginx:[^ ]*\)$/\1/p' docker-compose.yaml | head -n 1)"
[[ -n "$image" ]] || { echo "no nginx image in docker-compose.yaml" >&2; exit 2; }

containers=()
cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    for name in "${containers[@]}"; do
      echo "--- logs of $name" >&2
      docker logs "$name" 2>&1 | tail -n 20 >&2 || true
    done
  fi
  for name in "${containers[@]}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
  docker network rm "$net" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

failures=0
check() { # description, expected, actual
  if [[ "$2" == "$3" ]]; then
    printf 'ok    %s -> %s\n' "$1" "$3"
  else
    printf 'FAIL  %s: expected %q, got %q\n' "$1" "$2" "$3" >&2
    failures=$((failures + 1))
  fi
}

docker network create --internal "$net" >/dev/null

# Upstream stand-in: answers every request with the X-Forwarded-For it got.
mkdir -p "${TMPDIR:-/tmp}"
echo_conf="$(mktemp "${TMPDIR:-/tmp}/realip-echo.XXXXXX")"
chmod 0644 "$echo_conf"
cat >"$echo_conf" <<'EOF'
server {
    listen 8000;
    listen 8010;
    listen 8020;
    location / {
        default_type text/plain;
        return 200 "$http_x_forwarded_for";
    }
}
EOF
start() { # name, extra docker run arguments...
  local name="$1"
  shift
  containers+=("$name")
  docker run -d --name "$name" --network "$net" "$@" >/dev/null
}
start "$prefix-echo" --network-alias mail-ui --network-alias mcp --network-alias approval-ui \
  -v "$echo_conf:/etc/nginx/conf.d/default.conf:ro" "$image"
# Two client containers: "proxy" plays the trusted reverse proxy, "outsider"
# any other peer. Requests are sent from them with busybox wget.
start "$prefix-proxy" --entrypoint sleep "$image" 600
start "$prefix-outsider" --entrypoint sleep "$image" 600
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$1"; }
proxy_ip="$(ip_of "$prefix-proxy")"
outsider_ip="$(ip_of "$prefix-outsider")"
echo "proxy peer $proxy_ip, outsider peer $outsider_ip"

gateway() { # mode, trusted proxies ("" = default)
  local name="$prefix-gw-$1"
  start "$name" --read-only \
    --tmpfs /var/cache/nginx:rw,noexec,nosuid,size=16m \
    --tmpfs /var/run:rw,noexec,nosuid,size=1m \
    --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    --security-opt no-new-privileges:true --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SETGID --cap-add SETUID \
    --env-file "$root/deploy/nginx/real-ip/$1.env" \
    -e "EVERGARDEN_GATEWAY_TRUSTED_PROXIES=$2" \
    -v "$root/deploy/nginx/evergarden-gateway.conf:/etc/nginx/conf.d/default.conf:ro" \
    -v "$root/deploy/nginx/real-ip:/etc/nginx/real-ip:ro" \
    --entrypoint /bin/sh "$image" /etc/nginx/real-ip/entrypoint.sh nginx -g 'daemon off;'
  local deadline=$((SECONDS + 30))
  until docker exec "$prefix-proxy" wget -q -O /dev/null "http://$name:8080/gateway-healthz" 2>/dev/null; do
    if ((SECONDS > deadline)); then
      echo "gateway $name did not start" >&2
      exit 1
    fi
    sleep 1
  done
}

seen() { # from-container, gateway mode, header...
  local from="$1" mode="$2"
  shift 2
  local args=()
  for header in "$@"; do args+=(--header "$header"); done
  docker exec "$from" wget -q -O - "${args[@]}" "http://$prefix-gw-$mode:8080/" 2>/dev/null
}

forged=("X-Forwarded-For: 203.0.113.66" "CF-Connecting-IP: 203.0.113.77" "X-Real-IP: 203.0.113.88")

echo "== direct"
gateway direct ""
check "direct, forged XFF and CF headers" "$outsider_ip" "$(seen "$prefix-outsider" direct "${forged[@]}")"
check "direct, from a would-be proxy" "$proxy_ip" \
  "$(seen "$prefix-proxy" direct "X-Forwarded-For: 198.51.100.7")"

echo "== proxy (only the proxy container trusted)"
gateway proxy "$proxy_ip/32"
check "proxy, chain 'spoof, real' from the trusted proxy" "198.51.100.7" \
  "$(seen "$prefix-proxy" proxy "X-Forwarded-For: 203.0.113.66, 198.51.100.7")"
check "proxy, IPv6 client from the trusted proxy" "2001:db8::7" \
  "$(seen "$prefix-proxy" proxy "X-Forwarded-For: 2001:db8::7")"
check "proxy, forged headers from an untrusted peer" "$outsider_ip" \
  "$(seen "$prefix-outsider" proxy "${forged[@]}")"
check "proxy, CF-Connecting-IP ignored" "198.51.100.7" \
  "$(seen "$prefix-proxy" proxy "X-Forwarded-For: 198.51.100.7" "CF-Connecting-IP: 203.0.113.77")"
check "proxy, trusted proxy without XFF" "$proxy_ip" "$(seen "$prefix-proxy" proxy)"

echo "== proxy (default trusted ranges)"
docker rm -f "$prefix-gw-proxy" >/dev/null
gateway proxy ""
check "proxy default, chain from a private-range peer" "198.51.100.7" \
  "$(seen "$prefix-proxy" proxy "X-Forwarded-For: 203.0.113.66, 198.51.100.7")"

echo "== cloudflare (only the proxy container trusted)"
gateway cloudflare "$proxy_ip/32"
edge4="173.245.48.10"
edge6="2606:4700::6810:1"
check "cloudflare, Cloudflare hop, IPv4 client" "198.51.100.23" \
  "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: $edge4" "CF-Connecting-IP: 198.51.100.23")"
check "cloudflare, Cloudflare hop, IPv6 client" "2001:db8:1::23" \
  "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: $edge4" "CF-Connecting-IP: 2001:db8:1::23")"
check "cloudflare, IPv6 Cloudflare hop" "198.51.100.23" \
  "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: $edge6" "CF-Connecting-IP: 198.51.100.23")"
check "cloudflare, non-Cloudflare hop with forged CF-Connecting-IP" "198.51.100.9" \
  "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: 198.51.100.9" "CF-Connecting-IP: 203.0.113.77")"
check "cloudflare, untrusted peer forging XFF and CF-Connecting-IP" "$outsider_ip" \
  "$(seen "$prefix-outsider" cloudflare "X-Forwarded-For: $edge4" "CF-Connecting-IP: 203.0.113.77")"
for junk in "abc" "1.2.3" "198.51.100.1, 198.51.100.2" "203.0.113.5:80" "[2001:db8::1]" \
  "2001:db8::g" "unknown" "999.1.1.1"; do
  check "cloudflare, junk CF-Connecting-IP '$junk'" "$edge4" \
    "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: $edge4" "CF-Connecting-IP: $junk")"
done
check "cloudflare, two CF-Connecting-IP headers" "$edge4" \
  "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: $edge4" "CF-Connecting-IP: 198.51.100.1" \
    "CF-Connecting-IP: 198.51.100.2")"
check "cloudflare, Cloudflare hop without CF-Connecting-IP" "$edge4" \
  "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: $edge4")"
# A cloudflared tunnel container is a trusted peer that sends the client in
# both X-Forwarded-For and CF-Connecting-IP; the client resolves either way.
check "cloudflare, cloudflared-style peer" "198.51.100.31" \
  "$(seen "$prefix-proxy" cloudflare "X-Forwarded-For: 203.0.113.66, 198.51.100.31" \
    "CF-Connecting-IP: 198.51.100.31")"

echo "== invalid settings stop the gateway"
invalid() { # description, mode env value, trusted value
  local name="$prefix-invalid"
  local output
  if output="$(docker run --rm --name "$name" --network none --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=8m \
    -e "EVERGARDEN_GATEWAY_REAL_IP=$2" -e "EVERGARDEN_GATEWAY_TRUSTED_PROXIES=$3" \
    -v "$root/deploy/nginx/evergarden-gateway.conf:/etc/nginx/conf.d/default.conf:ro" \
    -v "$root/deploy/nginx/real-ip:/etc/nginx/real-ip:ro" \
    --entrypoint /bin/sh "$image" /etc/nginx/real-ip/entrypoint.sh nginx -t 2>&1)"; then
    check "$1 is refused" "refused" "started: $output"
  else
    check "$1 is refused" "refused" "refused"
  fi
}
invalid "unknown mode" "cloudfare" ""
invalid "trusted proxy hostname" "proxy" "proxy.example.com"
invalid "trust everything" "proxy" "0.0.0.0/0"
invalid "malformed IPv6 trusted proxy" "proxy" "2001:db8::zz/64"
invalid "IPv6 trusted proxy nginx cannot parse" "cloudflare" "2001:::1"
invalid "'none' mixed with addresses" "proxy" "none 10.0.0.0/8"

rm -f "$echo_conf"
if ((failures)); then
  echo "$failures check(s) failed" >&2
  exit 1
fi
printf '\ngateway real-IP smoke passed\n'
