# The record

The server writes down what happens on it in SQLite: in memory by default, or in a file that outlives restarts. It's
there to look at, and it holds what the server can't get from its settings: denied tokens, users invited while it runs,
and who was made an admin. Keep it on file to keep those across restarts.

```sh
WILDBURROW_DATABASE=/data/wildburrow.db wildburrow serve
sqlite3 /data/wildburrow.db "SELECT host, path, status FROM requests ORDER BY at DESC LIMIT 20"
```

## Settings

| Variable | Default | |
|---|---|---|
| `WILDBURROW_DATABASE` | in memory | A file to keep the record in; made, with its directories, if it isn't there |
| `WILDBURROW_DATABASE_RECORD` | `activity` | How much: `everything`, `activity` or `minimal` |
| `WILDBURROW_DATABASE_KEEP` | forever on file, `1d` in memory | How long a finished row is kept, or `never` to keep it |
| `WILDBURROW_DATABASE_PURGE_EVERY` | `1d` on file, `1h` in memory | How often the purge runs, once there's a KEEP |
| `WILDBURROW_DATABASE_TRAFFIC_MAX` | no cap | Bytes of traffic kept per connection with `everything` |

- `activity` keeps every table but the traffic itself: who logged in and how, sessions and what ended them, every
  command, tunnels and their names, locks, passwords and links with their counts, login attempts, link opens,
  hand-off codes, connections and every request on them with its status, certificates and DNS changes, and the
  server's log lines.
- `everything` keeps that and the bytes crossing each tunnel both ways, zlib'd when smaller. That's after TLS and after
  the lock, so what your app's own users send, their passwords and cookies included, ends up in the file.
  `WILDBURROW_DATABASE_TRAFFIC_MAX` cuts each connection's capture short, marking it truncated.
- `minimal` keeps only what's live, each row going as it ends: no history.
- Nothing secret is kept but invited users' password hashes (argon2, salted): no lock secret, password, token, link
  key, invite or hand-off code, only digests of them, and a link's key is cut out of the paths and answers recorded.
  Users, their keys and invites are kept whatever RECORD says, and never purged.
- Anyone who can write the file can let someone in, by adding a user or a key to it; keep it private (it's made 0600).
  The server reads users at start, so a change to the file shows only after a restart, and is refused if it makes a
  name both the settings' and the database's.

## The file

- A new file is made private (0600, its directories 0700) and marked as wildburrow's. A file that isn't, or one written
  by a newer wildburrow, stops the server rather than being overwritten. One from an older wildburrow is brought up to
  date when the server opens it, all of it or none.
- Users are written at once; the rest waits for the next batch.
- Writes wait for the next batch, about a second, so a busy tunnel doesn't mean a write per request.
- With a KEEP, a purge runs at start and then every PURGE_EVERY, taking whatever finished longer ago than KEEP, a batch
  at a time. Live rows are never purged. Without one, nothing is ever deleted.

## Tables

`runs`, `logs`, `identities`, `tokens`, `auth_attempts`, `sessions`, `commands`, `tunnels`, `tunnel_names`, `locks`,
`credentials`, `link_opens`, `login_attempts`, `handoff_codes`, `connections`, `requests`, `traffic`,
`certificates`, `dns_changes`, `users`, `user_keys` and `invites`, and the events. The schema, with what each column
holds, is [wildburrow/store/schema.sql](../wildburrow/store/schema.sql) and the changes since it in
[wildburrow/store/migrations](../wildburrow/store/migrations).

## Events

Every change to `users`, `user_keys`, `invites`, an identity's user or name, and a token's denial is copied into
`<table>_events` by triggers, so a change made by hand is caught too: the row after the change (before it, for a
delete), whether it was an insert, update or delete, when, and a `context` saying who made it and from where.

```sh
sqlite3 /data/wildburrow.db "SELECT at, label, name, admin, context FROM users_events ORDER BY event_id"
```

- The context names the admin's user and identity, their session, transport, address and command; `{"by":
  "settings"}` for the settings' users brought in at start, `"join"`, `"login"` or `"purge"` for what those do.
- No context means the change didn't come through the server: someone edited the file.
- No password hash or invite digest is copied: `password_set` and `password_changed_at` show a password's changes.
