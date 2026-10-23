# Plugins

Transports, auth methods and DNS providers are plugins registered through entry points: `wildburrow.transports`,
`wildburrow.auth` and `wildburrow.dns`. Install a package that registers one and select it by name, as in
`WILDBURROW_AUTH=key,mine`.

## Settings

A plugin class has a `Settings` dataclass and is constructed with it. Its fields are filled from
`WILDBURROW_<NAME>_*` for transports, `WILDBURROW_AUTH_<NAME>_*` and `WILDBURROW_DNS_<NAME>_*`, and become `serve`
options the same way: a field `api_key` on DNS plugin `zone` is `WILDBURROW_DNS_ZONE_API_KEY` and
`--dns-zone-api-key`. A field without a default is required; a `ConfigError` raised from `__init__` is reported with
the plugin's name.

## Transports

`start(ctx)` and `stop()` run with the server. A transport also declares:

- `methods`, a class attribute mapping the auth methods it carries to the credential each sends, such as
  `{"key": PublicKeyCredential}`. The server publishes the ones an installed auth plugin takes.
- `published()`, anything else a client needs to reach it, such as `{"port": 2222}`.

Each login opens a session with `ctx.sessions.open(identity, transport, peer, end)` and closes it with
`ctx.sessions.close(session)`; `end(reason)` must close the connection and tell the client why. A tunnel it binds has
a `session` attribute naming the session it came from, so `wildburrow tunnels` can list its names.

## Auth methods

`handles` names the credential types it checks, and `authenticate(credential, peer)` returns an `Identity` or `None`.
An identity's `names` limits what it may claim; `None` allows any free name. Its `expires`, in Unix seconds, ends
its sessions then; `None` never does.

## DNS providers

A DNS plugin implements `create_txt`, `delete_txt`, `ensure_cname` and `aclose`; see `wildburrow/dns/base.py`.
