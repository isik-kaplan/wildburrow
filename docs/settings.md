# Settings

Every setting is an option of `serve`, `service install` and `service edit`, and an environment variable for `serve`:
`--http-port 8080` is `WILDBURROW_HTTP_PORT=8080`.

- An option wins over an `--env-file` line, and an `--env-file` line over the environment.
- Adding `-file` to an option, or `_FILE` to a variable, reads the value from a file, for secrets and multi-line
  values: `--auth-key-authorized-keys-file=~/keys`, `WILDBURROW_DNS_CLOUDFLARE_API_TOKEN_FILE=/run/secrets/cf`.
- `wildburrow serve --help` lists them all, installed plugins included.
- In a terminal, `serve` asks for any required setting still missing, the server's and those of the plugins it uses.
  `--no-input` or `WILDBURROW_NO_INPUT=1` makes it fail instead.
- A service has no `--data-dir`; its service manager decides where its data goes.

## Server

| Variable | Default | |
|---|---|---|
| `WILDBURROW_DOMAIN` | required | Base domain tunnels live under |
| `WILDBURROW_TRANSPORTS` | `ssh` | Transport plugins: `ssh`, `websocket` |
| `WILDBURROW_AUTH` | `key` | Auth plugins, tried in order: `key`, `password`, `token` |
| `WILDBURROW_CLIENT_TRANSPORT` | first that works | The transport `wildburrow login` starts from |
| `WILDBURROW_CLIENT_AUTH` | its first in `AUTH` | The auth method `wildburrow login` starts from |
| `WILDBURROW_ADMINS` | `signers` | Who is an admin, by rules like `key` or `token:NAME`; [sessions.md](sessions.md) |
| `WILDBURROW_SEE` | `own` | Whose sessions people see: `none`, `own`, `admins`, `all`; see [sessions.md](sessions.md) |
| `WILDBURROW_KICK` | `own` | Whose sessions people can end, no further than `SEE` |
| `WILDBURROW_DATA_DIR` | `~/.local/state/wildburrow` | Host key, certificates, ACME account; `/data` in the image |
| `WILDBURROW_HTTP_HOST` / `_HTTP_PORT` | `0.0.0.0` / `80` | Plain HTTP listener |
| `WILDBURROW_HTTPS_HOST` / `_HTTPS_PORT` | `0.0.0.0` / `443` | TLS listener, when `WILDBURROW_DNS` is set |
| `WILDBURROW_HTTP_PROXY_PROTOCOL` / `_HTTPS_PROXY_PROTOCOL` | `false` | Require a PROXY v1/v2 header |
| `WILDBURROW_PROXY_TRUSTED` | private ranges | CIDRs allowed to send PROXY headers |
| `WILDBURROW_MAX_DEPTH` | `5` | Maximum labels in a name, `*` included |
| `WILDBURROW_MAX_HEADER_BYTES` | `65536` | Largest accepted request head |
| `WILDBURROW_HEADER_TIMEOUT` | `30` | Seconds for the TLS handshake and request head |

## Locks

Defaults for every [locked tunnel](locks.md), which a client can change for its own.

| Variable | Default | |
|---|---|---|
| `WILDBURROW_LOCK_PATH` | `/_wildburrow/login` | Login path on a locked tunnel's hosts |
| `WILDBURROW_LOCK_COOKIE` | `wildburrow` | Login cookie's name |
| `WILDBURROW_LOCK_HEADER` | `X-Wildburrow-Auth` | Header scripts log in with, as `USER:PASSWORD` |
| `WILDBURROW_LOCK_USER_HEADER` | `X-Wildburrow-User` | Header telling the app who logged in |
| `WILDBURROW_LOCK_EXPIRES` | when the browser closes | How long a login lasts, like `12h` |
| `WILDBURROW_LOCK_CONFIRM_LINKS` | `true` | A one-time link waits for a click |
| `WILDBURROW_LOCK_PAGE` / `_LINK_PAGE` / `_MESSAGE_PAGE` | built in | Your own pages, usually with `_FILE` |
| `WILDBURROW_LOCK_ATTEMPTS` | `10` | Failed logins a minute on one tunnel before it waits; server only |
| `WILDBURROW_LOCK_CODE_EXPIRES` | `10m` | How long a hand-off code is kept unused; server only |

## Certificates

| Variable | Default | |
|---|---|---|
| `WILDBURROW_DNS` | | DNS plugin for DNS-01: `cloudflare` |
| `WILDBURROW_DNS_MANAGE_RECORDS` | `false` | Create a CNAME for nested wildcards |
| `WILDBURROW_DNS_CLOUDFLARE_API_TOKEN` | | Token with DNS Edit and Zone Read |
| `WILDBURROW_ACME_DIRECTORY` | Let's Encrypt | ACME directory URL (staging, ZeroSSL, ...) |
| `WILDBURROW_ACME_EMAIL` | | ACME account contact |
| `WILDBURROW_ACME_PROPAGATION_SECONDS` | `30` | Wait after publishing a challenge record |
| `WILDBURROW_ACME_TIMEOUT_SECONDS` | `300` | Give up on an order after this long |
| `WILDBURROW_RENEW_BEFORE_DAYS` | `30` | Renew certificates in use this close to expiry |
| `WILDBURROW_RENEW_INTERVAL_SECONDS` | `43200` | How often to check for renewals |

## Transports

| Variable | Default | |
|---|---|---|
| `WILDBURROW_SSH_HOST` / `_SSH_PORT` | `0.0.0.0` / `2222` | SSH transport listener |
| `WILDBURROW_SSH_PUBLIC_PORT` | `SSH_PORT` | The SSH port published to clients, when a port mapping makes it differ |
| `WILDBURROW_SSH_LOGIN_TIMEOUT` | `30` | Seconds to finish an SSH login |
| `WILDBURROW_SSH_KEEPALIVE_INTERVAL` | `30` | Seconds between SSH keepalives |
| `WILDBURROW_WEBSOCKET_LOGIN_TIMEOUT` | `30` | Seconds to finish a websocket login |
| `WILDBURROW_WEBSOCKET_OPEN_TIMEOUT` | `10` | Seconds a client has to open a visitor stream |
| `WILDBURROW_WEBSOCKET_MAX_MESSAGE_BYTES` | `1048576` | Largest websocket message |

## Auth

| Variable | Default | |
|---|---|---|
| `WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS` | `~/.ssh/authorized_keys` | OpenSSH public keys, one per line |
| `WILDBURROW_AUTH_PASSWORD_HASH` | | argon2 hash from `wildburrow hash-password` |
| `WILDBURROW_AUTH_PASSWORD_MAX_FAILURES` | `5` | Failed passwords per address before blocking |
| `WILDBURROW_AUTH_PASSWORD_BLOCK_SECONDS` | `900` | How long failures count against an address |
| `WILDBURROW_AUTH_TOKEN_SIGNERS` | | Public keys whose signed tokens are accepted, one per line |
| `WILDBURROW_AUTH_TOKEN_DENY` | | Ids of signed tokens to refuse before they expire, comma-separated |
| `WILDBURROW_AUTH_TOKEN_HASHES` | | `name:sha256` lines from `wildburrow token NAME --hash` |

The token plugin needs `SIGNERS`, `HASHES` or both. See [tokens.md](tokens.md).
