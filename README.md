# wildburrow

Self-hosted HTTPS tunnels on your own domain, with wildcard names at any depth and certificates issued on demand.
It runs on Linux and macOS.

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
uv tool install wildburrow    # or: pipx install wildburrow
wildburrow login              # asks for the server and how to connect to it
wildburrow 3000 '*.foo'
wildburrow logout             # forgets the saved server
```

`login` keeps its answers in `~/.config/wildburrow/config.toml` until you log in again or out; nothing in it expires,
and every tunnel logs in afresh. Given options, `wildburrow login tunnel.example.com`, it asks nothing and saves them.

The server publishes how to log in to it, so `wildburrow login tunnel.example.com` is all a client needs: it starts
from the server's transport and auth method, offers only what the server runs, and fills in its SSH port. Options you
pass win, and one the server doesn't offer is refused with what it does. An older server that publishes nothing gets
the built-in defaults.

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

The websocket transport goes through an HTTP proxy from `HTTPS_PROXY` (or `HTTP_PROXY`) unless `NO_PROXY` excludes the
server. The ssh transport follows your SSH config, so a `ProxyJump` or `ProxyCommand` there applies.

Plain `ssh` works without the client:

```sh
ssh -T -p 2222 -R '*.foo:80:localhost:3000' tunnel.example.com
```

## Server

```sh
uv tool install 'wildburrow[server]'
wildburrow service install
```

`service install` asks for the domain, whether to serve HTTPS and through which DNS provider, and which keys may open
tunnels, then installs the server as a system service and starts it: systemd on Linux, launchd on macOS. It asks for
sudo itself. Point `tunnel.example.com` and `*.tunnel.example.com` at the server; DNS wildcards match any depth, so
deeper names resolve too.

```sh
wildburrow service status       # running or not, and where the logs are
wildburrow service edit         # the same questions, answered with the current settings
wildburrow service uninstall    # stop and remove it, asking whether to keep the certificates
```

Each of them takes the settings as options instead, and then asks nothing:

```sh
wildburrow service install --domain=tunnel.example.com --acme-email=you@example.com \
  --dns=cloudflare --dns-cloudflare-api-token-file=/root/cloudflare-token
wildburrow service edit --http-port=8080
wildburrow service uninstall --yes --purge
```

Without a DNS provider the server serves plain HTTP on port 80. With one, it gets wildcard certificates by proving it
owns the domain through DNS: port 80 redirects bound names to HTTPS, and port 443 terminates TLS, picking the
certificate by SNI. A request whose `Host` isn't covered by the certificate of its connection gets `421`. Try
`--acme-directory=https://acme-staging-v02.api.letsencrypt.org/directory` until the first certificate comes through, so
a mistake doesn't run into Let's Encrypt's rate limits.

Unless told otherwise, the service lets in the keys in your `~/.ssh/authorized_keys`, copied when you install or edit.
Its settings live in `/etc/wildburrow`, readable only by root and the service.

On Linux, an install under a home directory, which is where `uv tool install` puts it, runs as its owner with that
home read-only; one outside any home, like `/opt`, runs as a throwaway user that systemd makes up. Either way it can
bind ports 80 and 443 and nothing more. On macOS it runs as the install's owner, which macOS lets bind those ports.

### Foreground

`wildburrow serve` runs the server in the foreground with the same settings, read from options, an `--env-file` of
`KEY=VALUE` lines, or the environment:

```sh
sudo wildburrow serve --domain=tunnel.example.com
```

### Docker

```sh
docker run -d --restart unless-stopped -p 80:80 -p 443:443 -p 2222:2222 -v wildburrow-data:/data \
  -e WILDBURROW_DOMAIN=tunnel.example.com \
  -e WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" \
  -e WILDBURROW_DNS=cloudflare -e WILDBURROW_DNS_CLOUDFLARE_API_TOKEN=... \
  -e WILDBURROW_ACME_EMAIL=you@example.com \
  ghcr.io/isik-kaplan/wildburrow
```

The image comes in versions matching the package, for amd64 and arm64, and runs on Docker Desktop for macOS too.
`examples/docker-compose.traefik.yml` runs it behind Traefik with TLS passthrough and PROXY protocol, for hosts where
another proxy already owns ports 80 and 443.

### Settings

Every setting is an option of `serve`, `service install` and `service edit`, and an environment variable for `serve`:
`--http-port 8080` is `WILDBURROW_HTTP_PORT=8080`, and an option wins over the variable. Adding `-file` to an option,
or `_FILE` to a variable, reads the value from a file, for secrets and multi-line values:
`--auth-key-authorized-keys-file=~/keys`. `wildburrow serve --help` lists them all, plugins included. A service has
no `--data-dir`; its service manager decides where its data goes.

| Variable | Default | |
|---|---|---|
| `WILDBURROW_DOMAIN` | required | Base domain tunnels live under |
| `WILDBURROW_TRANSPORTS` | `ssh` | Transport plugins: `ssh`, `websocket` |
| `WILDBURROW_AUTH` | `key` | Auth plugins, tried in order: `key`, `password`, `token` |
| `WILDBURROW_CLIENT_TRANSPORT` / `_CLIENT_AUTH` | first that works | What `wildburrow login` starts from; by default the first transport in `TRANSPORTS` any auth plugin works over, and its first method in `AUTH` order |
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
| `WILDBURROW_SSH_PUBLIC_PORT` | `SSH_PORT` | The SSH port published to clients, when a port mapping makes it differ |
| `WILDBURROW_WEBSOCKET_OPEN_TIMEOUT` | `10` | Seconds a client has to open a visitor stream |
| `WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS` | `~/.ssh/authorized_keys` | OpenSSH public keys, one per line |
| `WILDBURROW_AUTH_PASSWORD_HASH` | | argon2 hash from `wildburrow hash-password` |
| `WILDBURROW_AUTH_PASSWORD_MAX_FAILURES` | `5` | Failed passwords per address before blocking |
| `WILDBURROW_AUTH_PASSWORD_BLOCK_SECONDS` | `900` | How long failures count against an address |
| `WILDBURROW_AUTH_TOKEN_HASHES` | | `name:sha256` lines from `wildburrow token NAME` |
| `WILDBURROW_DNS_CLOUDFLARE_API_TOKEN` | | Token with DNS Edit and Zone Read |

## Plugins

Transports, auth methods and DNS providers are plugins registered through entry points: `wildburrow.transports`,
`wildburrow.auth` and `wildburrow.dns`. A plugin class has a `Settings` dataclass, filled from
`WILDBURROW_<NAME>_*` (transports), `WILDBURROW_AUTH_<NAME>_*` or `WILDBURROW_DNS_<NAME>_*`, and is constructed with
it. Its fields become `serve` options the same way. A transport also declares `methods`, the auth methods it carries
mapped to the credential each sends, and `published()`, anything else a client needs to reach it. A DNS plugin
implements `create_txt`, `delete_txt`, `ensure_cname` and `aclose`; see `wildburrow/dns/base.py`.
Install a package that registers an entry point and select it by name.

## Development

```sh
uv sync --all-extras
uv run pytest -n auto                                # needs Docker for the Pebble ACME tests
uv run pytest -n auto -m "not acme and not system"   # without Docker
uv run pytest -m system --no-cov tests/system        # installs the real service; CI runs it on Linux and macOS
uv run ruff check . && uv run ruff format --check .
```

Coverage stays at 100%, and every mutant has to be killed. The mutation run re-tests only what changed since the last
run in `mutants/`, both source and tests; CI keeps that directory cached between runs.

```sh
uv run python -m scripts.mutation run          # re-test what changed
uv run python -m scripts.mutation run --full   # re-test everything
uv run python -m scripts.mutation run --shard commands   # one shard: commands, service, client, ...
```

CI runs each shard as a job of its own with its own cache, so a cold run takes minutes and a red shard says where
to look. There is one pass: each mutant runs against the tests traced to it, the test that killed it last time and
those that killed its siblings first, and a survivor is a test to write. mutmut leaves decorated functions alone,
so a decorated function only hands off to a plain one.

Every push to `master` runs the tests and the mutation run, then publishes to PyPI and `ghcr.io` when the version in
`pyproject.toml` isn't on PyPI yet.
