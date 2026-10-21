# Client

## Install and log in

```sh
uv tool install wildburrow    # or: pipx install wildburrow
wildburrow login tunnel.example.com
wildburrow 3000 myapp         # https://myapp.tunnel.example.com
```

`login` asks the server how to log in to it and starts from that: the server publishes its transports, the auth
methods each takes, its SSH port, and the transport and method it suggests. So for most servers the server's name is
all a client needs.

- Options you pass win: `--transport`, `--auth`, `--ssh-port`, `--identity`, `--token`, `--user`, `--url`. One the
  server doesn't offer is refused, naming what it does offer.
- Given no server in a terminal, `login` asks for each setting, offering only what the server runs and starting from
  its suggestions. A choice it doesn't need to ask, because the server offers only one, is skipped and said.
- A server older than 0.2.0 publishes nothing, so `login` falls back to `ssh` and `key` and says so.
- The answers live in `~/.config/wildburrow/config.toml`, readable only by you, until you log in again or
  `wildburrow logout`. Nothing in it expires; every tunnel logs in afresh.

```sh
wildburrow login tunnel.example.com --transport websocket --identity ~/.ssh/id_ed25519
wildburrow login tunnel.example.com --token wb1...      # a token someone minted for you
wildburrow logout                                       # forget the saved server
```

## Opening a tunnel

```sh
wildburrow 3000 myapp '*.myapp'               # both names, to local port 3000
wildburrow 3000 myapp --server other.example.com
WILDBURROW_TOKEN=wb1... wildburrow 3000 app    # the token from the environment instead
```

`wildburrow PORT NAME...` is short for `wildburrow connect PORT NAME...`. Every `login` option works here too, for
this run only. `--local-host` is where the local port listens (default `localhost`).

Requests reach your app unchanged, so websockets, server-sent events and streaming responses work as they do locally.
With HTTPS, visitors use `wss://` and your app sees plain `ws://`.

## Transports

| Transport | How it connects | Auth methods |
|---|---|---|
| `ssh` | your `ssh` binary, port 2222, one `-R` per name | `key`, `password` |
| `websocket` | `wss://tunnel.example.com` on 443 | `key` (signed with `ssh-keygen -Y sign`), `password`, `token` |

`websocket` gets through networks that only let HTTPS out. Tokens and `wildburrow names` only work over it.

## Staying up

When the connection drops, the client reconnects and binds its names again, waiting `--retry-delay` seconds (default 1)
and doubling up to `--retry-max` (default 30). Over websocket it also waits for a server that isn't reachable yet.

- A refused login or a refused name ends the client instead: retrying wouldn't change the answer.
- `--no-reconnect` makes any disconnect end it.
- `login` saves these flags like the others, and `connect` overrides them for a run.
- Reconnecting takes back your own names straight away, even before the server has noticed the old connection is gone.

## Proxies

The websocket transport goes through an HTTP proxy from `HTTPS_PROXY` (or `HTTP_PROXY`) unless `NO_PROXY` excludes the
server, and so does `login` when it asks the server how to log in. The ssh transport follows your SSH config, so a
`ProxyJump` or `ProxyCommand` there applies.

## Without the client

Plain `ssh` works too:

```sh
ssh -T -p 2222 -R '*.foo:80:localhost:3000' tunnel.example.com
```
