# wildburrow

Self-hosted HTTPS tunnels on your own domain: expose a local port as `myapp.tunnel.example.com`, or a whole wildcard
like `*.myapp.tunnel.example.com`, at any depth, with certificates issued on demand. Linux and macOS.

## Server

```sh
uv tool install 'wildburrow[server]'
wildburrow service install    # asks for the domain, DNS provider and keys, then runs as a systemd or launchd service
```

Point `tunnel.example.com` and `*.tunnel.example.com` at it. Or with Docker: `ghcr.io/isik-kaplan/wildburrow`.

## Client

```sh
uv tool install wildburrow
wildburrow login tunnel.example.com
wildburrow 3000 myapp '*.myapp'    # https://myapp.tunnel.example.com and https://<anything>.myapp.tunnel.example.com
```

`wildburrow` alone, in a terminal, asks what to do. Add `--lock alice:pw` or `--link` to let in only the people you
choose, with a password or a one-time link.

## Documentation

The full index is [docs/INDEX.md](https://github.com/isik-kaplan/wildburrow/blob/master/docs/INDEX.md).

- [Client](https://github.com/isik-kaplan/wildburrow/blob/master/docs/client.md) - logging in, the ssh and websocket
  transports, staying connected, proxies
- [Names](https://github.com/isik-kaplan/wildburrow/blob/master/docs/names.md) - wildcards at any depth, binding,
  `wildburrow names`, several local sites behind one router
- [Tokens](https://github.com/isik-kaplan/wildburrow/blob/master/docs/tokens.md) - letting people in with tokens you
  mint and sign yourself
- [Locks](https://github.com/isik-kaplan/wildburrow/blob/master/docs/locks.md) - passwords and one-time links in
  front of a tunnel
- [Sessions](https://github.com/isik-kaplan/wildburrow/blob/master/docs/sessions.md) - who is connected, ending
  sessions, and admins
- [Server](https://github.com/isik-kaplan/wildburrow/blob/master/docs/server.md) - the service, HTTPS, Docker and
  Traefik
- [Settings](https://github.com/isik-kaplan/wildburrow/blob/master/docs/settings.md) - every setting
- [Plugins](https://github.com/isik-kaplan/wildburrow/blob/master/docs/plugins.md) and
  [development](https://github.com/isik-kaplan/wildburrow/blob/master/docs/development.md)

What changed in each release: [CHANGELOG.md](https://github.com/isik-kaplan/wildburrow/blob/master/CHANGELOG.md).

## License

MIT
