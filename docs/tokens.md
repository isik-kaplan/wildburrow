# Tokens

Tokens let people in without an SSH key of their own on the server. You mint them on your own machine, signed with
your SSH key, and the server only needs that key's public half. A token carries its holder's name, the names it may
claim, when it was minted and when it expires, and the signature vouches for all of it. The server checks the
signature and needs nothing else to let a token in; minting tells it about the token anyway, so admins can list it.

**If the key that signs tokens is lost or leaks,** take it out of `WILDBURROW_AUTH_TOKEN_SIGNERS` first: whoever has
it can mint more. That ends every token it signed; mint new ones, with a new key, for whoever should keep access.

## On the server

Tokens travel over websocket only, so the server needs that transport and `token` among its auth methods:

```sh
WILDBURROW_TRANSPORTS=websocket
WILDBURROW_AUTH=key,token
WILDBURROW_AUTH_TOKEN_SIGNERS="ssh-ed25519 AAAA... you@laptop"
```

`WILDBURROW_AUTH_TOKEN_SIGNERS` takes public keys one per line, in `authorized_keys` format; `_FILE` reads them from a
file. Any of them can mint.

## Minting

```sh
wildburrow tokens new alice --names 'alice,*.alice'          # good for 7 days
wildburrow tokens new ci --names any --expires never --yes   # any free name, no expiry
```

```
alice gets a token for alice, *.alice until 2026-10-28 12:00 UTC.
Only an admin denying it, or its name, stops it sooner.
? Mint it? No
```

- `--names` is required: names with `*` standing for any one label, or `any` for every free name.
- `--expires` takes `30m`, `12h`, `7d`, `2w` or `never`, and defaults to `7d`.
- It asks before signing, defaulting to no. `--yes` skips the question; without a terminal it's required.
- It signs with `--identity`, else the saved login's key, else the first of `~/.ssh/id_ed25519`, `id_ecdsa` and
  `id_rsa`, through `ssh-keygen`, which asks for the key's passphrase if it has one.
- It registers the token with the saved login's server, or `--server`, before printing it: its id, name, names and
  expiry, never the token itself. That takes an admin login there.
- It prints the token's id and the lines to run on the other device:

```
token for alice, valid until 2026-10-28 12:00 UTC, for: alice, *.alice
id: 3f9a0c4e1b2d7a65 (`wildburrow tokens deny 3f9a0c4e1b2d7a65` stops it early)

on alice's device:
  uv tool install wildburrow
  wildburrow login tunnel.example.com --auth token --token wb1...
```

All of a holder's tokens are one identity, so a newer token for `alice` takes over the names an older one holds.

### Minting offline

When the token can't be registered (no saved login, not an admin there, the server unreachable or older than 0.8.0),
it isn't minted: in a terminal it asks `Mint it without registering it?`, defaulting to no, and otherwise fails. Pass
`--offline` to mint without trying. The token works all the same; the server just doesn't list it until it's used.

Every command then says so, on stderr, until it's registered:

```
1 token minted with --offline isn't registered with tunnel.example.com; run: wildburrow tokens sync
```

`wildburrow tokens sync` registers them, and `wildburrow tokens` does on its way to listing.
`wildburrow config set sync-notice off` (or `WILDBURROW_CLIENT_SYNC_NOTICE=off`) stops the notice.

## Listing

```sh
wildburrow tokens
```

```
ID                NAME   NAMES           EXPIRES               LAST USED             STATE   SERVER
3f9a0c4e1b2d7a65  alice  alice, *.alice  2026-10-28 12:00 UTC  2026-10-22 09:14 UTC  -       tunnel.example.com
91e2b7d0c3f4a58e  ci     any name        never                 -                     denied  tunnel.example.com
denied: every token for bob minted before 2026-10-21 08:00 UTC
```

It lists every token the saved login's server has: those registered when minted, and those it met when they logged
in, whoever minted them. That takes an admin login there; otherwise it says why and lists this machine's alone. It
adds the tokens minted on this machine, logged in `~/.local/state/wildburrow/tokens.jsonl` (`XDG_STATE_HOME` moves it)
without the token itself, marking any not yet registered `unregistered`.

A server keeps its list in its database: one with `WILDBURROW_DATABASE` keeps it across restarts, one in memory forgets
it, which minting and listing say. Mints from before 0.8.0 are listed once they've been used.

## Ending a token early

A token's tunnels end when it expires (see [sessions.md](sessions.md#tokens-end-their-tunnels)). To stop one sooner:

```sh
wildburrow tokens deny 3f9a0c4e1b2d7a65      # by the id `tokens` lists; ends its sessions now
wildburrow tokens deny --name alice          # every token for alice minted until now, used or not
```

- Only an admin of the server can deny tokens. The server refuses them from then on, and keeps refusing them after a
  restart when it keeps its record on file ([database.md](database.md)); in memory, a restart forgets it.
- `--name` needs no ids: it refuses every signed token for that name minted before now, plus a minute for a minting
  machine's clock running ahead, even ones the server has never seen. Tokens for the name minted after that work, so
  mint the replacements a minute later. It touches only signed tokens, never a key or password login of that name.
- Or list ids in `WILDBURROW_AUTH_TOKEN_DENY` (comma-separated) and restart the server.
- Keep expiries short and mint again when needed.

## Random tokens

`wildburrow tokens new NAME --hash` makes the older kind: a random token, and a line of its hash for
`WILDBURROW_AUTH_TOKEN_HASHES`. These need the server's settings changed for each one, but end the moment their line
is removed. Both kinds work side by side.
