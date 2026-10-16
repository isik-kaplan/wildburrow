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

The client keeps the tunnel up: when the connection drops, it reconnects and binds its names again, waiting
`--retry-delay` seconds (default 1) and doubling up to `--retry-max` (default 30). Over websocket it also waits for a
server that isn't reachable yet. A refused login or a rejected name ends the client instead, and `--no-reconnect` makes
any disconnect end it. `login` saves these flags like the others and `connect` overrides them. Binding a name you
already hold moves it to the new connection; other identities are refused.

Plain `ssh` works without the client:

```sh
ssh -T -p 2222 -R '*.foo:80:localhost:3000' tunnel.example.com
```

## Server

### Docker

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

`examples/docker-compose.traefik.yml` runs it behind Traefik with TLS passthrough and PROXY protocol, for hosts where
another proxy already owns ports 80 and 443.

### Without Docker

Install it as a tool and run `wildburrow serve`. It needs to bind ports below 1024, so give it
`CAP_NET_BIND_SERVICE` rather than running it as root. A systemd service does that for a dynamic user:

```sh
# as root
UV_TOOL_DIR=/opt/wildburrow UV_TOOL_BIN_DIR=/usr/local/bin UV_PYTHON_INSTALL_DIR=/opt/wildburrow/python \
  uv tool install 'wildburrow[server] @ git+https://github.com/isik-kaplan/wildburrow'
mkdir -p /etc/wildburrow && cp ~/.ssh/id_ed25519.pub /etc/wildburrow/authorized_keys
cat > /etc/wildburrow/env <<'EOF'
WILDBURROW_DOMAIN=tunnel.example.com
WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS_FILE=/etc/wildburrow/authorized_keys
EOF
chmod 600 /etc/wildburrow/env
```

`/etc/systemd/system/wildburrow.service`:

```ini
[Unit]
Description=wildburrow tunnel server
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/wildburrow serve
EnvironmentFile=/etc/wildburrow/env
Environment=WILDBURROW_DATA_DIR=%S/wildburrow
DynamicUser=yes
StateDirectory=wildburrow
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now wildburrow
journalctl -u wildburrow -f
```

### Settings

Every setting can also be read from a file by adding `_FILE` to its name, for secrets and multi-line values:
`WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS_FILE=/etc/wildburrow/authorized_keys`.

| Variable | Default | |
|---|---|---|
| `WILDBURROW_DOMAIN` | required | Base domain tunnels live under |
| `WILDBURROW_TRANSPORTS` | `ssh` | Transport plugins: `ssh`, `websocket` |
| `WILDBURROW_AUTH` | `key` | Auth plugins, tried in order: `key`, `password`, `token` |
| `WILDBURROW_DATA_DIR` | `~/.local/state/wildburrow` | Host key, certificates, ACME account; `/data` in the image |
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
| `WILDBURROW_DNS_CLOUDFLARE_API_TOKEN` | | Token with DNS Edit and Zone Read |

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
