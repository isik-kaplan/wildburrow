# wildburrow

Self-hosted HTTPS tunnels on your own domain, with wildcard names at any depth and certificates issued on demand.

```sh
wildburrow 3000 myapp           # https://myapp.tunnel.example.com
wildburrow 3000 '*.foo'         # https://<anything>.foo.tunnel.example.com
wildburrow 3000 '*.bar.foo'     # https://<anything>.bar.foo.tunnel.example.com
```

A wildcard covers exactly one label, like a TLS wildcard certificate: `*.foo` serves `api.foo` but not `x.api.foo`.
An exact name wins over a wildcard. Quote `*` names so your shell doesn't expand them.

Requests reach your local app unchanged, so websockets, server-sent events and streaming responses work as they do
locally. With HTTPS, visitors use `wss://` and your app sees plain `ws://`.

When a name needs a certificate that doesn't exist yet, the server gets `*.<parent>` from an ACME CA through a DNS-01
challenge while your client waits, then confirms the bind. Later binds under the same parent are instant.

## Client

```sh
uv tool install git+https://github.com/isik-kaplan/wildburrow    # or: pipx install git+https://...
wildburrow login tunnel.example.com
wildburrow 3000 '*.foo'
```

Two transports are available:

| Transport | How it connects | Auth methods |
|---|---|---|
| `ssh` (default) | your `ssh` binary, port 2222, one `-R` per name | `key`, `password` |
| `websocket` | `wss://tunnel.example.com` on 443 | `key` (signed with `ssh-keygen -Y sign`), `password`, `token` |

```sh
wildburrow login tunnel.example.com --transport websocket --auth key --identity ~/.ssh/id_ed25519
wildburrow login tunnel.example.com --transport websocket --auth token --token wb_...
WILDBURROW_TOKEN=wb_... wildburrow 3000 app     # token from the environment
```

Plain `ssh` works without the client:

```sh
ssh -T -p 2222 -R '*.foo:80:localhost:3000' tunnel.example.com
```

## Server

```sh
docker build -t wildburrow .
docker run -p 80:80 -p 443:443 -p 2222:2222 -v wildburrow-data:/data \
  -e WILDBURROW_DOMAIN=tunnel.example.com \
  -e WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" \
  -e WILDBURROW_DNS=cloudflare -e WILDBURROW_DNS_CLOUDFLARE_API_TOKEN=... \
  -e WILDBURROW_ACME_EMAIL=you@example.com \
  wildburrow
```

Point `tunnel.example.com` and `*.tunnel.example.com` at the server. DNS wildcards match any depth, so deeper names
resolve too; set `WILDBURROW_DNS_MANAGE_RECORDS=true` to also create a `*.<parent>` CNAME for each nested wildcard.

Without `WILDBURROW_DNS`, the server serves plain HTTP on `WILDBURROW_HTTP_PORT` and issues no certificates. With it,
port 80 redirects bound names to HTTPS and port 443 terminates TLS, picking the certificate by SNI. A request whose
`Host` isn't covered by the certificate of its connection gets `421`.

`examples/docker-compose.traefik.yml` runs it behind Traefik with TLS passthrough and PROXY protocol.

### Settings

| Variable | Default | |
|---|---|---|
| `WILDBURROW_DOMAIN` | required | Base domain tunnels live under |
| `WILDBURROW_TRANSPORTS` | `ssh` | Transport plugins: `ssh`, `websocket` |
| `WILDBURROW_AUTH` | `key` | Auth plugins, tried in order: `key`, `password`, `token` |
| `WILDBURROW_DATA_DIR` | `/data` | SSH host key, certificates, ACME account |
| `WILDBURROW_HTTP_HOST` / `_HTTP_PORT` | `0.0.0.0` / `80` | Plain HTTP listener |
| `WILDBURROW_HTTPS_HOST` / `_HTTPS_PORT` | `0.0.0.0` / `443` | TLS listener, when `WILDBURROW_DNS` is set |
| `WILDBURROW_HTTP_PROXY_PROTOCOL` / `_HTTPS_PROXY_PROTOCOL` | `false` | Require a PROXY v1/v2 header |
| `WILDBURROW_PROXY_TRUSTED` | private ranges | CIDRs allowed to send PROXY headers |
| `WILDBURROW_MAX_DEPTH` | `5` | Maximum labels in a name, `*` included |
| `WILDBURROW_MAX_HEADER_BYTES` | `65536` | Largest accepted request head |
| `WILDBURROW_HEADER_TIMEOUT` | `30` | Seconds for the TLS handshake and request head |
| `WILDBURROW_DNS` | | DNS plugin for DNS-01: `cloudflare` |
| `WILDBURROW_DNS_MANAGE_RECORDS` | `false` | Create a CNAME for nested wildcards |
| `WILDBURROW_ACME_DIRECTORY` | Let's Encrypt | ACME directory URL (staging, ZeroSSL, ...) |
| `WILDBURROW_ACME_EMAIL` | | ACME account contact |
| `WILDBURROW_ACME_PROPAGATION_SECONDS` | `30` | Wait after publishing a challenge record |
| `WILDBURROW_RENEW_BEFORE_DAYS` | `30` | Renew certificates in use this close to expiry |
| `WILDBURROW_SSH_PORT` | `2222` | SSH transport port (`_HOST`, `_LOGIN_TIMEOUT` too) |
| `WILDBURROW_WEBSOCKET_OPEN_TIMEOUT` | `10` | Seconds a client has to open a visitor stream |
| `WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS` | | OpenSSH public keys, one per line |
| `WILDBURROW_AUTH_PASSWORD_HASH` | | argon2 hash from `wildburrow hash-password` |
| `WILDBURROW_AUTH_PASSWORD_MAX_FAILURES` | `5` | Failed passwords per address before blocking |
| `WILDBURROW_AUTH_PASSWORD_BLOCK_SECONDS` | `900` | How long failures count against an address |
| `WILDBURROW_AUTH_TOKEN_HASHES` | | `name:sha256` lines from `wildburrow token NAME` |
| `WILDBURROW_DNS_CLOUDFLARE_API_TOKEN` | | Token with DNS Edit and Zone Read (or `_API_TOKEN_FILE`) |

## Plugins

Transports, auth methods and DNS providers are plugins registered through entry points: `wildburrow.transports`,
`wildburrow.auth` and `wildburrow.dns`. A plugin class has a `Settings` dataclass, filled from
`WILDBURROW_<NAME>_*` (transports), `WILDBURROW_AUTH_<NAME>_*` or `WILDBURROW_DNS_<NAME>_*`, and is constructed with
it. A DNS plugin implements `create_txt`, `delete_txt`, `ensure_cname` and `aclose`; see `wildburrow/dns/base.py`.
Install a package that registers an entry point and select it by name.

## Development

```sh
uv sync --all-extras
uv run pytest -n auto                 # needs Docker for the Pebble ACME tests
uv run pytest -n auto -m "not acme"   # without Docker
uv run ruff check . && uv run ruff format --check .
```
