# Reverse proxy examples

Evergarden's gateway serves the mail UI, the approval pages and `/mcp` on one
origin. It publishes `127.0.0.1:8788` by default (`EVERGARDEN_HTTP_BIND` and
`EVERGARDEN_HTTP_PORT` in `.env`). On a single machine you can use it directly
at `http://127.0.0.1:8788`. For access from other machines, put a TLS reverse
proxy in front of it and keep the gateway bound to loopback.

| Proxy | Example | Upstream |
|-------|---------|----------|
| Caddy | [`Caddyfile.example`](Caddyfile.example) | `127.0.0.1:8788` |
| nginx | [`nginx.conf.example`](nginx.conf.example) | `127.0.0.1:8788` |
| Nginx Proxy Manager | [`../nginx/npm-mail-host-advanced.conf.example`](../nginx/npm-mail-host-advanced.conf.example) | `evergarden-gateway:8080` on the proxy's Docker network (`compose.proxy.yaml`) |

After choosing a domain, tell Evergarden its public origin. On a fresh install:

```sh
./deploy/setup --public-origin https://mail.example.com
```

Add `--real-ip proxy` to that command (`--real-ip cloudflare` when Cloudflare
is in front). On an existing install, edit `.local/run/runtime.env`:

```sh
EVERGARDEN_MCP_RESOURCE=https://mail.example.com/mcp
EVERGARDEN_MAIL_UI_APPROVAL_URL=https://mail.example.com
EVERGARDEN_MICROSOFT_OAUTH_REDIRECT_URI=https://mail.example.com/oauth/callback/microsoft
EVERGARDEN_GOOGLE_OAUTH_REDIRECT_URI=https://mail.example.com/oauth/callback/google
EVERGARDEN_ADMIN_SECURE_COOKIES=true
```

MCP bearer tokens are bound to `EVERGARDEN_MCP_RESOURCE`. After changing it,
create new API keys in the mail UI. Also set the new resource as the `audience`
of the `mail-ui` entry in `.local/run/compatibility_tokens.json`. Then run
`docker compose up -d`.

Rules for every proxy:

- Terminate TLS and forward `Host`, `X-Forwarded-Proto`, `X-Forwarded-Host`
  and `X-Forwarded-For`. Replace `X-Forwarded-For` with the address you saw,
  as the shipped examples do. Appending to a client-supplied header is safe
  only when `EVERGARDEN_GATEWAY_TRUSTED_PROXIES` is narrowed to this proxy's
  own address or network: with the default list (all of RFC 1918), a client
  from a private range (LAN, VPN) whose address is trusted could put any
  address in front of it and choose its throttle key. Set `EVERGARDEN_GATEWAY_REAL_IP=proxy` in `.env` (`cloudflare` when
  Cloudflare is in front of this proxy, which must then pass
  `CF-Connecting-IP` through). The gateway then takes the client from the
  right-most `X-Forwarded-For` entry that is not a trusted proxy and sends the
  apps that one address; the web UI keys its sign-in throttle on it. In the
  default `direct` mode the gateway ignores forwarding headers, so behind a
  proxy every remote client shares the proxy's bucket of failed sign-ins (15
  per 15 minutes by default). See
  [docs/configuration.md](../../docs/configuration.md#real-client-address).
- Only the proxy may reach the gateway port in `proxy` and `cloudflare` modes
  while a trusted-proxy list is in effect: keep `EVERGARDEN_HTTP_BIND=127.0.0.1`
  (never `0.0.0.0` or a LAN address). The exception, Cloudflare connecting
  straight to the gateway with `EVERGARDEN_GATEWAY_TRUSTED_PROXIES=none`, is
  described in
  [docs/configuration.md](../../docs/configuration.md#real-client-address).
  The default trusted ranges (loopback, RFC 1918, `fc00::/7`) cover a proxy on
  this host or on a Docker network; narrow them with
  `EVERGARDEN_GATEWAY_TRUSTED_PROXIES` when you can.
- Do not buffer `/mcp`, and allow long reads there (MCP streams).
- Do not add basic auth, forward-auth or `auth_request`. Evergarden has its
  own administrator login, and MCP uses bearer tokens.
- Clear caller-supplied `Remote-User`, `Remote-Groups`, `Remote-Email`,
  `Remote-Name` and `X-Evergarden-Proxy-Secret` headers.
