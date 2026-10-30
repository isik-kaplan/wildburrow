# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Users, and invites.** Everyone who logs in is a user. `wildburrow users invite NAME` gives an admin a one-time code;
  the person runs `wildburrow join SERVER CODE` to set their own password, SSH key, or both, and an alias to log in
  under. `wildburrow users` lists everyone, `users promote` and `users demote` make an invited user an admin or not,
  and `users remove` ends their logins and sessions. The settings' users stay the settings': they can't be invited,
  changed or removed from the database, and a name is either the settings' or the database's. Kept in
  `WILDBURROW_DATABASE`; the server and these commands warn when it's in memory. See [docs/users.md](docs/users.md).
- **Every change to who may log in is recorded as an event**, with who made it and from where: users, their keys,
  invites, which user an identity is, and token denials, in `<table>_events`, written by triggers so a hand edit to
  the file shows up too, with no one behind it. No password hash or invite code is ever copied.

### Changed

- **Each password user has their own password.** `WILDBURROW_AUTH_PASSWORD_HASH`, one password anyone could log in
  with under any name, is gone: `WILDBURROW_AUTH_PASSWORD_USERS` takes a `name:argon2hash` line per user, and a
  password logs in only its own user. `wildburrow passwords hash NAME` prints the line. Each user is now their own
  identity, for `tunnels`, `kick` and links, and `WILDBURROW_ADMINS` takes `password:NAME`. A server still given
  `WILDBURROW_AUTH_PASSWORD_HASH` won't start, saying what to use instead.
- **A key's comment names its user and device**: `isik@laptop` and `isik@phone` are both `isik`, so they see and end
  each other's sessions, links and tunnels as their own. Each key still logs in, and is listed, as itself, and
  `WILDBURROW_ADMINS=key:isik` makes every key of `isik`'s an admin.
- **Your own means your user's**, whichever of their keys, tokens or password they logged in with.
- **The database's schema is 2.** A file from 0.5.0 is brought up to date when the server opens it.

## [0.5.0] - 2026-10-26

### Added

- **`wildburrow connect` alone, in a terminal, asks** for the port and names, whether to lock the tunnel and who may
  get in, and, when you want to change them, where the local port listens and every lock setting. The menu's "Open a
  tunnel" runs it, so it asks the same.
- **`kick` takes several targets and works out what each means**: a session id, an identity or a name held. A target
  whose readings land on different sessions is refused, with each reading listed; `--who` and `--name` still pick
  one, and repeat. Given nothing in a terminal, `kick` lists the sessions and asks which to end. Every target is ended
  over one login.
- **`links end` takes several names**, all ended over one login.
- **The server keeps a record** of what happens on it in SQLite, in memory by default or on file with
  `WILDBURROW_DATABASE`: who logged in, sessions and what ended them, commands, tunnels, locks and their logins,
  every request through a tunnel with its status, certificates, DNS changes and its own log lines.
  `WILDBURROW_DATABASE_RECORD` says how much (`everything` adds the traffic itself, `minimal` keeps only what's live)
  and `WILDBURROW_DATABASE_KEEP` for how long. See [docs/database.md](docs/database.md).
- **`wildburrow tokens deny ID`** stops a token logging in and ends its sessions, for an admin of the server, without
  a restart; on file, it stays denied across restarts.
- **A link can share a password's name**: `--lock anil --links anil` lets anil in either way, both logging in as
  `anil`. Ending the name ends both.
- **Links that work more than once.** `--link-uses N` or `any`, and `links add --uses N`; `links` says how often each
  has been used.
- **`links` says more**: each password's or link's state, its uses, how many logins it has had, when it was last seen
  and when it expires. The counts and last-seen times now survive a client's reconnect and a server restart.
- **Tunnels keep search engines away.** Every response through a tunnel carries `X-Robots-Tag: noindex, nofollow`, as
  does everything the server answers itself. A client lets its tunnel be indexed with `--index`, or keeps it out with
  `--no-index`; the server's `WILDBURROW_INDEX` decides the default (`opt-in`, so tunnels stay out unless asked) or
  forbids indexing outright (`never`). Needs a 0.5.0 server for a client to choose.
- **The lock checks every request on a connection**, not only the first, so a kept-alive connection can't carry a
  request past it or the lock's cookie to your app. A later request on the connection for another host is answered
  `421 Misdirected Request` instead of reaching the first one's tunnel.
- **An admin kept to their own sessions is told so.** When the server's `WILDBURROW_SEE` or `WILDBURROW_KICK` is `own`
  or `none`, an admin whose `tunnels` lists no one, or whose `kick` reaches no one, hears which setting stops them.
  The server now says how far it reaches in its answers to both.
- **`wildburrow config`** lists every client setting, its value and where it comes from; `config set NAME VALUE` saves
  one in config.toml and `config unset NAME` forgets it. Saved settings sit below options, variables and answers, and a
  question starts from what's saved.
- **Every client setting has a variable**: `WILDBURROW_CLIENT_` and its name, as in `WILDBURROW_CLIENT_SERVER`,
  `WILDBURROW_CLIENT_LOCAL_HOST` or `WILDBURROW_CLIENT_AUTH`.
- **`names`, `tunnels`, `kick` and `links` take the connection options** `connect` takes (`--token`, `--auth`,
  `--transport` and the rest), for that run.
- **`--lock-page-file`, `--lock-link-page-file` and `--lock-message-page-file`** read a page from a file, as the
  `_FILE` variables do; `--lock-page` and the others take the HTML itself.

### Changed

- **Commands come in noun groups.** `wildburrow token NAME` is `wildburrow tokens new NAME`; `wildburrow link URL` is
  `wildburrow links add URL`; `wildburrow links --end WHO` is `wildburrow links end WHO...`. `tokens` and `links` alone
  still list. `wildburrow hash-password` is `wildburrow passwords hash`. `logout` forgets only the login, keeping
  settings saved with `config set`. The old spellings are gone.
- **Lock options no longer depend on where they go.** `--lock` always takes `USER[:PASSWORD]`, and `--lock-guest`
  makes up a user; `--link` makes one link, and `--links N|LABELS` takes the count or labels `--link` took.
  `WILDBURROW_LINK` is now a yes or no for one link; the count or labels it held go in `WILDBURROW_LINKS`, and
  `WILDBURROW_LOCK_GUEST` stands for `--lock-guest`.
- **Client variables start with `WILDBURROW_CLIENT_`**, so they never read as the server's: `WILDBURROW_TOKEN` is
  `WILDBURROW_CLIENT_TOKEN`, and `WILDBURROW_LOCK`, `_LOCK_FILE`, `_LOCK_*`, `_LINK`, `_LINKS` and `_LINK_EXPIRES`
  each gain `CLIENT_` the same way.
- **The server's suggestion to clients** is `WILDBURROW_SUGGESTED_TRANSPORT` and `WILDBURROW_SUGGESTED_AUTH`, not
  `WILDBURROW_CLIENT_TRANSPORT` and `WILDBURROW_CLIENT_AUTH`.
- **Admins see and end everyone's sessions by default.** `WILDBURROW_SEE` and `WILDBURROW_KICK` default to `admins`
  instead of `own`: an admin's `tunnels` lists everyone who isn't an admin, with their addresses, and `kick` reaches
  them. Others still reach only their own, and admins still don't reach each other. Set both to `own` for the old
  behaviour.
- **The lock's pages have a new look**, sharp-cornered and compact, in light or dark as the visitor's browser
  prefers.
- **`--lock-page FILE` and its two siblings** are `--lock-page-file FILE` and its siblings.
- A setting that can't be, given as an option or a variable, is a usage error: the usage line, then `Error:` and what
  was wrong, naming the option or variable as it was given.
- A client setting read from a `_FILE` variable, such as `WILDBURROW_LOCK_FILE`, loses only its final line break,
  not all the whitespace around it.

## [0.4.1] - 2026-10-24

### Fixed

- **A token logs in by token.** `wildburrow login SERVER --token TOKEN` saved the server's suggested method instead,
  so on a server suggesting `key` the token was never sent and the login failed. A given token now means
  `--auth token`, over a transport that takes it; `--auth` still wins when given.
- **`WILDBURROW_TOKEN` logs in by token** for that run, over websocket, whatever the saved login says. Options given
  still win.
- **The login line `wildburrow token` prints** spells out `--auth token`, so it works on clients before 0.4.1 too.

### Changed

- A token over ssh is refused, whether from `--token` or `--auth token`, rather than saved for a login ssh can't make.

## [0.4.0] - 2026-10-24

### Added

- **Locked tunnels.** `--lock USER[:PASSWORD]` and `--link [N|LABELS]` put a login page the server serves in front of
  a tunnel, so nothing reaches your app until a visitor logs in with a password or a one-time link. Passwords can be
  typed, given or made up; links wait for a click, so chat previews don't use them up. See
  [docs/locks.md](docs/locks.md).
- **One login covers every host of a locked tunnel**, `foo` and `*.foo` alike, carried from host to host by a one-time
  code that works only in the browser that asked for it.
- **Your app is told who logged in** in `X-Wildburrow-User`, and never sees the lock's own cookie or header. Scripts
  log in with `X-Wildburrow-Auth: USER:PASSWORD`.
- **`wildburrow link URL`** mints one more link to a locked tunnel of yours, landing on URL, and
  **`wildburrow links`** lists who may get in and who has; `--end WHO` ends a password or link and logs out whoever
  used it.
- **`WILDBURROW_LOCK_*` settings** default every lock's login path, cookie and header names, login lifetime, link
  confirmation and pages, and limit failed logins per tunnel. A client changes all but the limits for its own tunnel.
- **`wildburrow` alone asks whether to lock** a tunnel it opens.

### Changed

- **A dropped connection keeps a tunnel's lock**: the client reconnects with the same logins and links.

## [0.3.0] - 2026-10-23

### Added

- **`wildburrow tunnels`** lists who is connected: each session's id, identity, auth method and transport, names, when
  it started and expires, and, for admins and on your own sessions, the client's address. See
  [docs/sessions.md](docs/sessions.md).
- **`wildburrow kick`** ends sessions by id, by a name held (`--name`) or by identity (`--who`), over either transport.
  For a token still valid, it prints the id to add to `WILDBURROW_AUTH_TOKEN_DENY`.
- **`WILDBURROW_ADMINS`, `WILDBURROW_SEE` and `WILDBURROW_KICK`** decide who is an admin and how far anyone sees and
  ends other sessions. By default the token signers' keys are admins and everyone reaches only their own sessions, so a
  token used on two machines can end one from the other.
- **`wildburrow` alone in a terminal asks what to do**: open a tunnel, log in, mint a token, see or end sessions, or set
  up or change a server here.
- **`wildburrow serve` asks in a terminal** for required settings still missing, its own and its plugins'.
- **`--no-input` and `WILDBURROW_NO_INPUT`** turn off every question; a command fails instead of asking.
- **`service install` and `service edit`** ask who is an admin and who sees and ends sessions.

### Changed

- **A token's tunnels end when it expires**, within the minute's grace the login check allows. Before, a tunnel opened
  with a token outlived it.
- **A client whose session the server ended stops** instead of reconnecting, printing `closed: ` and why, over both
  transports.
- **A command that needs a server logs in first** when run in a terminal with none saved, instead of failing.

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
