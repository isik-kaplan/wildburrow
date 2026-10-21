# Tokens

Tokens let people in without an SSH key of their own on the server. You mint them on your own machine, signed with
your SSH key, and the server only needs that key's public half. It keeps no record of them: a token carries its
holder's name, the names it may claim and when it expires, and the signature vouches for all three.

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
wildburrow token alice --names 'alice,*.alice'          # good for 7 days
wildburrow token ci --names any --expires never --yes   # any free name, no expiry
```

```
alice gets a token for alice, *.alice until 2026-10-28 12:00 UTC.
It can't be withdrawn before then, short of rotating the signer key.
? Mint it? No
```

- `--names` is required: names with `*` standing for any one label, or `any` for every free name.
- `--expires` takes `30m`, `12h`, `7d`, `2w` or `never`, and defaults to `7d`.
- It asks before signing, defaulting to no, since nothing withdraws a token once it's out. `--yes` skips the question;
  without a terminal it's required.
- It signs with `--identity`, else the saved login's key, else the first of `~/.ssh/id_ed25519`, `id_ecdsa` and
  `id_rsa`, through `ssh-keygen`, which asks for the key's passphrase if it has one.
- It prints the token's id and the lines to run on the other device, naming the saved login's server or `--server`:

```
token for alice, valid until 2026-10-28 12:00 UTC, for: alice, *.alice
id: 3f9a0c4e1b2d7a65 (for WILDBURROW_AUTH_TOKEN_DENY, should it need stopping early)

on alice's device:
  uv tool install wildburrow
  wildburrow login tunnel.example.com --token wb1...
```

All of a holder's tokens are one identity, so a newer token for `alice` takes over the names an older one holds.

## Listing

```sh
wildburrow tokens
```

```
ID                NAME   NAMES           EXPIRES                       SERVER
3f9a0c4e1b2d7a65  alice  alice, *.alice  2026-10-28 12:00 UTC          tunnel.example.com
91e2b7d0c3f4a58e  ci     any name        never                         tunnel.example.com
```

Each mint is logged on the machine that made it, in `~/.local/state/wildburrow/tokens.jsonl` (`XDG_STATE_HOME`
moves it), without the token itself. The server can't list tokens: it never stores them.

## Ending a token early

With nothing kept on the server, a token can't be revoked on its own. Instead:

- Keep expiries short and mint again when needed.
- List its id in `WILDBURROW_AUTH_TOKEN_DENY` (comma-separated) and restart the server. A token that would have expired
  anyway can come off the list then; one that never expires stays.
- Replace the signing key in `WILDBURROW_AUTH_TOKEN_SIGNERS` to end every token it signed, then mint again for whoever
  should keep access.

## Random tokens

`wildburrow token NAME --hash` makes the older kind: a random token, and a line of its hash for
`WILDBURROW_AUTH_TOKEN_HASHES`. These need the server's settings changed for each one, but end the moment their line
is removed. Both kinds work side by side.
