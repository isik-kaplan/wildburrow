# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-21

### Added

- **Tokens you mint and sign yourself.** `wildburrow token alice --names 'alice,*.alice'` signs a token with your SSH
  key on your own machine. It carries the holder's name, the names it may claim (`any` for every free name) and an
  expiry (`--expires`, `7d` by default, or `never`). A server that lists the key in `WILDBURROW_AUTH_TOKEN_SIGNERS`
  accepts it without storing anything, so letting someone in no longer means changing the server's settings. It asks
  before signing, since a token can't be withdrawn, unless given `--yes`, and prints the line to run on the other
  device. See [docs/tokens.md](docs/tokens.md).
- **`wildburrow tokens`** lists what the current machine has minted, from a log kept without the tokens themselves.
- **`WILDBURROW_AUTH_TOKEN_DENY`** refuses signed tokens by id before they expire.
- **`wildburrow names`** lists the names bound on the server right now and which are yours, without saying who holds
  the others.
- **The server says how to log in to it.** `GET /_wildburrow/info` publishes each transport's auth methods, the SSH
  port, and a default transport and auth method. `wildburrow login SERVER` starts from it, offers only what the server
  runs, and refuses an option it doesn't. Against an older server it falls back to the built-in defaults.
- **`WILDBURROW_CLIENT_TRANSPORT` and `WILDBURROW_CLIENT_AUTH`** choose the published defaults, and
  **`WILDBURROW_SSH_PUBLIC_PORT`** the published SSH port when a port mapping changes it.

### Changed

- **A tunnel's names are bound all or none.** Binding `free taken other` used to bind `free` before refusing `taken`,
  certificates and all. Now if any name is taken, invalid or outside a token's names, none are bound, and the refusal
  names every one in the way. A client binding several names needs a 0.2.0 server; 0.1.0 clients still work with one.
- **`wildburrow token NAME` mints signed tokens.** The random tokens checked against `WILDBURROW_AUTH_TOKEN_HASHES` are
  `wildburrow token NAME --hash`, and keep working beside signed ones.
- **`WILDBURROW_AUTH_TOKEN_HASHES` is optional** once `WILDBURROW_AUTH_TOKEN_SIGNERS` is set; the token plugin needs one
  of them.
- **The server won't start when no one could log in.** Token auth with only the ssh transport used to start and refuse
  everyone; it now stops with an error saying no auth method works over any transport.

## [0.1.0] - 2026-10-18

The first release.

### Added

- **Tunnels on wildcard names at any depth.** `wildburrow 3000 '*.bar.foo'` serves `<anything>.bar.foo` under the
  server's domain, and an exact name wins over a wildcard.
- **Two transports:** SSH remote forwards on port 2222, plain `ssh -R` included, and a websocket control channel on 443
  that gets through networks that only let HTTPS out.
- **Three auth methods:** SSH keys, argon2 passwords with per-address blocking, and hashed tokens.
- **Certificates on demand.** `*.<parent>` is issued through ACME DNS-01 the first time a name under it is bound, and
  renewed while in use. Cloudflare is built in.
- **TLS by SNI**, PROXY protocol v1 and v2 from trusted networks, and plain HTTP redirected to HTTPS.
- **A client that keeps tunnels up,** reconnecting with backoff and going through `HTTPS_PROXY` when set.
- **`wildburrow login`, `logout`, `serve`, `hash-password` and `token`,** asking for what they need in a terminal.
- **`wildburrow service install`, `edit`, `uninstall` and `status`** on systemd and launchd.
- **Every setting as an option,** an environment variable, a `_FILE` variable or an `--env-file` line.
- **Plugins** for transports, auth methods and DNS providers, through entry points.
- **A multi-arch image** on ghcr.io and a Traefik example.
