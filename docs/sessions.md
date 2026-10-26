# Sessions

Every login is a session: a tunnel's connection, or a command like `wildburrow names` while it runs. The server keeps
them in memory only, so a restart forgets them along with every tunnel, and nothing is written to disk.

## Seeing them

```sh
wildburrow tunnels
```

```
ID            WHO           VIA              NAMES           SINCE                 EXPIRES               FROM
a1b2c3d4e5f6  alice         token/websocket  alice, *.alice  2026-10-23 14:02 UTC  2026-10-23 14:07 UTC  203.0.113.4
0f0f0f0f0f0f  laptop (you)  key/ssh          myapp           2026-10-23 09:15 UTC  -                     198.51.100.9
```

It logs in the way a tunnel would, with the saved login or `--server`, and lists every other session you may see. A
session marked `(you)` is your own identity on another connection or machine. `FROM` is the client's address, shown
only to admins and on your own sessions.

## Ending them

```sh
wildburrow kick a1b2c3d4e5f6      # one session, by its id
wildburrow kick alice bob         # by identity, or by a name held
wildburrow kick --name alice      # only whichever session holds the name
wildburrow kick --who alice       # only the sessions of that identity
```

Each target is tried as a session id, an identity and a name held. When the readings that match land on different
sessions, as with alice the identity and a name `alice` someone else holds, `kick` ends nothing, lists each reading,
and asks for `--who` or `--name`. Given nothing in a terminal, it lists the sessions and asks which to end.

It doesn't ask first otherwise. The ended client prints `closed: ended by <you>` and stops instead of reconnecting, over both
transports.

Ending a session doesn't take the credential away. When it could come back, `kick` says so:

- A signed token that hasn't expired logs in again until it does. `kick` prints its id, for
  `WILDBURROW_AUTH_TOKEN_DENY` if it has to stop sooner; see [tokens.md](tokens.md#ending-a-token-early).
- A key or password logs in again until it's removed from the server's settings.

Ending one of your own sessions, like a tunnel left running on another machine, needs no such note.

## Tokens end their tunnels

A tunnel opened with a signed token ends when the token expires, up to a minute later to allow for clocks that
disagree, the same minute the login check allows. The client prints `closed: the token expired` and stops. A token
minted with `--expires never` has nothing to end it.

## Who sees and ends what

Three settings decide it. `WILDBURROW_ADMINS` says who is an admin, as a comma-separated list of rules; anyone matching
one is.

| Rule | Who it makes an admin |
|---|---|
| `signers` | Key logins whose key is also in `WILDBURROW_AUTH_TOKEN_SIGNERS` (the default) |
| `key`, `token`, `password` | Everyone logging in with that method |
| `key:SHA256:...` or `key:COMMENT` | One key, by fingerprint or its comment in the authorized keys |
| `token:NAME` | One token holder |
| `all` | Everyone who can log in |
| `none` | No one |

`signers` needs the key in `WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS` too, since an admin logs in like anyone else. Whoever
holds a signer key can already mint a token for any name, so making them admins grants nothing new.

`WILDBURROW_SEE` and `WILDBURROW_KICK` each take a level, and each level allows what the one before it does:

| Level | Who reaches whose sessions |
|---|---|
| `none` | No one, not even their own |
| `own` | Everyone their own |
| `admins` | Admins also everyone who isn't an admin (the default) |
| `all` | Admins everyone, admins included |

An admin a level keeps to their own sessions is told so, with the setting that does it, when `tunnels` or `kick`
finds no one. Someone who isn't an admin never reaches past their own sessions. `KICK` can't reach further than `SEE`, and the server
won't start if it does.

### What counts as your own

The same identity: the same key, the same token holder (any of their tokens), or the same name line in
`WILDBURROW_AUTH_TOKEN_HASHES`. Everyone logged in with the password counts as one, since the password lets anyone pick
any name.

### Before widening them

- `ADMINS=token`, `password` or `all` makes a credential that can be copied into an admin credential: anyone holding a
  copy of the token, or the password, becomes an admin. An SSH key's private half stays on its machine.
- `KICK=all` lets any admin end every other admin's tunnels.
- `SEE=admins` or `all` shows admins who is connected, and from where.

`wildburrow service install` and `service edit` ask for all three.

## Over which transport

`tunnels` and `kick` go over websocket, so the server needs that transport, and they need a 0.3.0 server; an older one
is named as such. Sessions over SSH are listed and ended like any other, but can't run the commands themselves.
