# The record

The server writes down what happens on it in SQLite: in memory by default, or in a file that outlives restarts. Nothing
the server does depends on it; it's there to look at and to keep denied tokens denied.

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
- Nothing secret is kept: no lock secret, password, token, link key or hand-off code, only digests of them, and a link's
  key is cut out of the paths and answers recorded.

## The file

- A new file is made private (0600, its directories 0700) and marked as wildburrow's. A file that isn't, or one written
  by a newer wildburrow, stops the server rather than being overwritten.
- Writes wait for the next batch, about a second, so a busy tunnel doesn't mean a write per request.
- With a KEEP, a purge runs at start and then every PURGE_EVERY, taking whatever finished longer ago than KEEP, a batch
  at a time. Live rows are never purged. Without one, nothing is ever deleted.

## Tables

`runs`, `logs`, `identities`, `tokens`, `auth_attempts`, `sessions`, `commands`, `tunnels`, `tunnel_names`, `locks`,
`credentials`, `link_opens`, `login_attempts`, `handoff_codes`, `connections`, `requests`, `traffic`,
`certificates` and `dns_changes`. The schema, with what each column holds, is
[wildburrow/store/schema.sql](../wildburrow/store/schema.sql).
