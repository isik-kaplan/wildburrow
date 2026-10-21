# Names

## Names and wildcards

```sh
wildburrow 3000 myapp           # https://myapp.tunnel.example.com
wildburrow 3000 '*.foo'         # https://<anything>.foo.tunnel.example.com
wildburrow 3000 '*.bar.foo'     # https://<anything>.bar.foo.tunnel.example.com
```

- A wildcard covers exactly one label, like a TLS wildcard certificate: `*.foo` serves `api.foo` but not `x.api.foo`.
  Bind `'*.api.foo'` too for that level.
- An exact name wins over a wildcard: with `*.foo` bound to you and `api.foo` to someone else, `api.foo` reaches them.
- Quote `*` names so your shell doesn't expand them.
- Labels are a-z, 0-9 and `-`, and a name has at most `WILDBURROW_MAX_DEPTH` labels (default 5), `*` included.

With HTTPS, a name needs a certificate for `*.<its parent>`. The first name under a parent waits a few seconds while the
server gets one through DNS-01; later names under the same parent are instant.

## Binding

All the names of one tunnel are bound together. If any is taken by someone else, isn't a valid name, or is outside
what your token may claim, none are bound, and the refusal names every one in the way:

```
rejected: api is already bound by bob; pic is already bound by bob
```

A name you already hold moves to the new connection, so a reconnecting client takes its names straight back. Your
identity decides what's yours: the same SSH key, the same password user, or the same token holder.

A client binding several names at once needs a server of 0.2.0 or later.

## Who holds what

```sh
wildburrow names
```

```
NAME    HOLDER
*.mine  you
mine    you
pic     someone else
```

It logs in the way a tunnel does and lists the names bound right now, without saying who holds the others. It asks
over websocket, so the server needs that transport. `--server` asks another server.

## Several local sites behind one router

A local setup that serves `localhost`, `api.localhost` and `admin.localhost` from one router tunnels as a name and its
wildcard, both to the router's port:

```sh
wildburrow 80 myapp '*.myapp'
```

Requests reach the router unchanged, with the public host the visitor used, like `api.myapp.tunnel.example.com`. Add
those hosts to the router next to the local ones, so the app builds links, redirects and cookies for the name the
visitor is on. wildburrow has already handled TLS, so they're plain `http://` addresses. In Caddy:

```
localhost, http://myapp.tunnel.example.com {
	reverse_proxy localhost:3000
}

api.localhost, http://api.myapp.tunnel.example.com {
	reverse_proxy localhost:3001
}
```
