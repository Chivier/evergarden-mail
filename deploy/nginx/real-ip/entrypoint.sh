#!/bin/sh
# Gateway entrypoint (docker-compose.yaml runs it with /bin/sh, so it needs no
# exec bit). It renders the real-client-address configuration chosen by
# EVERGARDEN_GATEWAY_REAL_IP into a tmpfs, then hands over to the nginx image's
# own entrypoint. Any invalid value stops the gateway with a message; it never
# falls back to another mode.
#
#   EVERGARDEN_GATEWAY_REAL_IP          direct (default), proxy or cloudflare
#   EVERGARDEN_GATEWAY_TRUSTED_PROXIES  addresses/CIDRs of the reverse proxies,
#                                       separated by spaces or commas; "none"
#                                       trusts no proxy. Default below.
#
# Called without a command it only renders (the unit tests use that).
set -eu

snippets=/etc/nginx/real-ip
runtime=${EVERGARDEN_GATEWAY_RUNTIME_DIR:-/tmp/evergarden-gateway}
default_trusted="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ::1/128 fc00::/7"

fail() {
    echo "evergarden-gateway: $*" >&2
    exit 64
}

valid_ipv4() {
    case $1 in
        '' | *[!0-9.]* | .* | *. | *..*) return 1 ;;
    esac
    saved_ifs=$IFS
    IFS=.
    # shellcheck disable=SC2086 # split on dots on purpose
    set -- $1
    IFS=$saved_ifs
    [ $# -eq 4 ] || return 1
    for octet do
        [ ${#octet} -le 3 ] && [ "$octet" -le 255 ] || return 1
    done
}

check_entry() {
    entry=$1
    address=${entry%/*}
    limit=32
    case $address in
        *:*)
            limit=128
            case $address in *[!0-9A-Fa-f:.]*) fail "trusted proxy '$entry' is not an address or CIDR" ;; esac
            ;;
        *) valid_ipv4 "$address" || fail "trusted proxy '$entry' is not an address or CIDR" ;;
    esac
    case $entry in
        */*)
            prefix=${entry##*/}
            case $prefix in '' | *[!0-9]*) fail "trusted proxy '$entry' has an invalid prefix length" ;; esac
            [ ${#prefix} -le 3 ] && [ "$prefix" -ge 1 ] && [ "$prefix" -le "$limit" ] \
                || fail "trusted proxy '$entry' must have a prefix length of 1-$limit (never trust every address)"
            ;;
    esac
}

mode=${EVERGARDEN_GATEWAY_REAL_IP:-direct}
case $mode in
    direct | proxy | cloudflare) ;;
    *) fail "EVERGARDEN_GATEWAY_REAL_IP must be direct, proxy or cloudflare, not '$mode'" ;;
esac

trusted=${EVERGARDEN_GATEWAY_TRUSTED_PROXIES:-$default_trusted}
mkdir -p "$runtime"
list="$runtime/trusted-proxies.conf"
{
    echo "# Rendered by entrypoint.sh from EVERGARDEN_GATEWAY_TRUSTED_PROXIES."
    if [ "$trusted" != none ]; then
        count=0
        set -f
        for entry in $(printf '%s\n' "$trusted" | tr ',' ' '); do
            [ "$entry" != none ] || fail "'none' cannot be combined with addresses"
            check_entry "$entry"
            echo "set_real_ip_from $entry;"
            count=$((count + 1))
        done
        set +f
        [ "$count" -gt 0 ] || fail "EVERGARDEN_GATEWAY_TRUSTED_PROXIES lists no address"
    fi
} >"$list.new"
mv "$list.new" "$list"
printf 'include %s/%s.conf;\n' "$snippets" "$mode" >"$runtime/real-ip.conf"

if [ "$mode" = direct ]; then
    echo "evergarden-gateway: client address mode direct (forwarding headers ignored)"
else
    echo "evergarden-gateway: client address mode $mode; trusted proxies: $trusted"
fi

[ $# -gt 0 ] || exit 0
exec /docker-entrypoint.sh "$@"
