# Users

Everyone who logs in to the server is a user, and a user is a name. How they log in is one of their identities: each
key is its own, as is a password or a token, so `isik`'s laptop and phone show up apart but are both `isik`'s.

## Where users come from

| From | Who | Changed by |
|---|---|---|
| The settings | Each `WILDBURROW_AUTH_PASSWORD_USERS` line, each key's user in the authorized keys, each `WILDBURROW_AUTH_TOKEN_HASHES` name | The server's settings, and a restart |
| A signed token | Its holder, the first time they log in | Whoever holds a signer key |
| An invite | Someone an admin invited, once they join | Admins, while the server runs |

- **A key's user** is its comment up to `@`: `isik@laptop` and `isik@phone` are both `isik`, on the device after the
  `@`. A comment without `@` is the user, and a key without a comment is its own user, named by its fingerprint.
- **The settings' users** are copied into the database at every start, so everything about them can point at them.
  Nothing done while the server runs changes them. A name taken out of the settings stays, so its history does, but
  can't log in until it's back.
- **A name belongs to one place.** The database refuses to invite a name the settings have, and a server whose settings
  name a database user's name or alias won't start, saying which. A token signed for a database user's name doesn't
  log them in.

## Inviting

An admin invites someone by name; they set up their own login with the code, so the admin never knows their password.

```sh
wildburrow users invite carol            # good for 7 days; --expires 1h for less
```

```
invited carol, until 2026-11-06 18:00 UTC; they run:
  wildburrow join tunnel.example.com wbi_Jq3…
```

```sh
wildburrow join tunnel.example.com wbi_Jq3…                    # asks for a password, twice
wildburrow join tunnel.example.com wbi_Jq3… --key ~/.ssh/id_ed25519 --device laptop
wildburrow join tunnel.example.com wbi_Jq3… --no-password --key ~/.ssh/id_ed25519
wildburrow join tunnel.example.com wbi_Jq3… --alias c          # log in as carol or c
```

- `join` sets a password, a key, or both, and saves the login as `wildburrow login` would. The password travels over
  the encrypted connection and is kept only as an argon2 hash, salted in the hash itself.
- An invite works once, and a newer one for the same name ends the older. A new invite is also how someone who forgot
  their password sets a new one; what they already had stays unless they set it again.
- `--alias` gives one more name to log in under. `carol` stays the name in the record and in the admin rules.
- Joining needs the server's websocket transport.

## Managing them

```sh
wildburrow users                   # every user: where from, admin or not, how they log in
wildburrow users promote carol     # make an invited user an admin
wildburrow users demote carol
wildburrow users remove carol      # ends their sessions; their password, keys and invite go, their history stays
```

All four are for admins. Only invited users can be promoted, demoted or removed: who the settings make an admin
(`WILDBURROW_ADMINS`) stays one whatever the database says, and `demote` says so when someone still is. A removed user
can be invited again under the same name.

The admin rules apply to invited users' logins too: `WILDBURROW_ADMINS=key` makes every key an admin, the ones people
joined with included, and `password` every password. To keep invited users out of it, name your admins instead, as in
`key:SHA256:...` or `key:isik`.

## Without a database file

The database is in memory unless `WILDBURROW_DATABASE` names a file, and then invited users, and who was made an admin,
are lost when the server stops. The server warns of it at start, and `users`, `users invite` and the other commands
warn whoever runs them. Set `WILDBURROW_DATABASE` to a file to keep them.

## What's recorded

Every change to users, their keys, invites, which user an identity is, and token denials is kept as an event, a copy of
the row after the change, with who made it and from where: the admin's user and identity, their session, address and
command, or the server itself at start. A change made to the file by hand, outside the server, shows up with no one
behind it. No event holds a password hash or an invite's code; a password's change shows as that it's set and when.
See [database.md](database.md).
