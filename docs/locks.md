# Locked tunnels

A locked tunnel answers visitors with a login page from the server, and nothing reaches your app until they log in.
It isn't Basic auth: your app's own cookies and `Authorization` header pass through untouched.

## Locking a tunnel

```sh
wildburrow 3000 foo '*.foo' --lock alice --lock bob:baz --link 2
```

```
Password for alice (empty makes one up):
ready: https://foo.tunnel.example.com
ready: https://*.foo.tunnel.example.com
locked:
  alice   password: (the one you typed)
  bob     password: baz
  link-1  https://foo.tunnel.example.com/_wildburrow/login/link/8fK2…
  link-2  https://foo.tunnel.example.com/_wildburrow/login/link/Qm9x…
```

- `--lock USER:PASSWORD` lets USER in with PASSWORD. `--lock USER` asks for the password in a terminal, where an empty
  answer makes one up, and makes one up without a terminal. `--lock` alone makes up a username and a password.
- `--link` makes one one-time link, `--link 3` three, and `--link alice,bob` one labelled for each. A link logs its
  holder in without a password, once. `--link-expires 1h` stops unused links working after an hour.
- Both repeat and mix. Either one locks the tunnel; with only links, the login page has no form and says to ask for an
  invite link.
- What it prints is the only copy. The server keeps HMACs of the passwords and digests of the links, so a lost link
  can't be shown again; mint another with `wildburrow link`.
- `--lock` and `--link` without a value go after the names, or before another option, so they don't take the next
  word as theirs.
- `WILDBURROW_LOCK` takes `USER[:PASSWORD]` lines, or `WILDBURROW_LOCK_FILE` a file of them; `WILDBURROW_LINK` and
  `WILDBURROW_LINK_EXPIRES` stand for `--link` and `--link-expires`. An option wins over its variable.
- `wildburrow` alone asks whether to lock a tunnel it opens.

It needs the websocket transport and a 0.4.0 server. The client refuses to start rather than open the tunnel unlocked.

## What a visitor sees

Someone opening `https://admin.foo.tunnel.example.com/bar/baz?tab=2#settings` gets the login page, and after logging in
lands on that same address. The `#settings` part survives too, since browsers carry it across redirects.

**One login covers every host of the tunnel.** Logging in happens on the tunnel's first plain name, its home: `foo`
here. A host of the tunnel without a login sends the visitor to the home and back with a one-time code, which sets that
host's own cookie. The visitor types their password once, and each other host costs one quick redirect the first time
it's visited. A tunnel with only wildcard names logs in on the server's own domain instead.

**A link waits for a click.** Opening a link shows a Continue button, and only the click uses it up. Chat apps and
mail clients open links for their previews, and would otherwise use a link up before anyone clicked it.
`--no-lock-confirm-links` makes a link work as it opens. Once used, a link logs no one else in, and opening it again in
the browser that used it goes to the tunnel.

Two people opening the same tunnel log in separately. Each browser keeps its own cookie.

## What your app sees

- `X-Wildburrow-User: alice`, or a link's label, on every request let in. A visitor sending that header themselves has
  it removed.
- Never the lock's cookie or its header: the server takes both out.
- The login path, `/_wildburrow/login` by default, belongs to the lock on a locked tunnel. An open tunnel passes every
  path to your app.

The server checks the first request on each connection and then passes the connection through. Later requests on it
come from the same visitor, but may still carry the lock's cookie.

## Scripts

```sh
curl -H 'X-Wildburrow-Auth: alice:baz' https://foo.tunnel.example.com/api
```

The header takes a username and password from `--lock`. Links don't work in it.

## More links, and ending them

```sh
wildburrow link https://admin.foo.tunnel.example.com/bar     # one more, landing there
wildburrow link https://foo.tunnel.example.com --as carol --expires 1d
wildburrow links                                             # who may get in, and who has
wildburrow links --end bob                                   # ends bob's password or link
```

```
foo, *.foo
WHO     KIND      USED                         LAST SEEN
alice   password  2 logins                     2026-10-24 14:40 UTC
bob     password  -                            -
link-1  link      used 2026-10-24 14:05 UTC    2026-10-24 14:31 UTC
link-2  link      unused                       -
```

They log in the way a tunnel would and reach only tunnels of your own identity. Ending a password or a link logs out
everyone who logged in with it. `link` and `links` go over websocket, like `tunnels`.

## How long a login lasts

Until the browser closes, unless `--lock-expires 12h` or the server's `WILDBURROW_LOCK_EXPIRES` says otherwise.

- When the connection drops, the client reconnects with the same lock, so logins and links survive it, and a used
  link stays used.
- Stopping `wildburrow` and starting it again makes a new lock. That logs everyone out and ends every link.
- A server restart drops every tunnel and every login.

## Settings

The server sets every lock's defaults; a client changes them for its own tunnel. The client also reads its options
from variables of the same names.

| Client option | Server variable | Default | |
|---|---|---|---|
| `--lock-path` | `WILDBURROW_LOCK_PATH` | `/_wildburrow/login` | Login path on the tunnel's hosts |
| `--lock-cookie` | `WILDBURROW_LOCK_COOKIE` | `wildburrow` | Login cookie, sent as `__Host-wildburrow` over HTTPS |
| `--lock-header` | `WILDBURROW_LOCK_HEADER` | `X-Wildburrow-Auth` | Header scripts log in with |
| `--lock-user-header` | `WILDBURROW_LOCK_USER_HEADER` | `X-Wildburrow-User` | Header telling your app who logged in |
| `--lock-expires` | `WILDBURROW_LOCK_EXPIRES` | when the browser closes | How long a login lasts |
| `--[no-]lock-confirm-links` | `WILDBURROW_LOCK_CONFIRM_LINKS` | on | Links wait for a click |
| `--lock-page FILE` | `WILDBURROW_LOCK_PAGE_FILE` | built in | Login page |
| `--lock-link-page FILE` | `WILDBURROW_LOCK_LINK_PAGE_FILE` | built in | Page a link opens with |
| `--lock-message-page FILE` | `WILDBURROW_LOCK_MESSAGE_PAGE_FILE` | built in | Page for the lock's messages |
| | `WILDBURROW_LOCK_ATTEMPTS` | `10` | Failed logins a minute on one tunnel before it waits |
| | `WILDBURROW_LOCK_CODE_EXPIRES` | `10m` | How long a hand-off code is kept unused |

### Your own pages

A page is HTML with `$name` placeholders, at most 64 KB. The built-in pages in
[wildburrow/edge/pages](../wildburrow/edge/pages) make a starting point.

| Page | Placeholders | What it does |
|---|---|---|
| login | `$title`, `$action`, `$hidden`, `$error` | POSTs `username`, `password` and `$hidden` to `$action` |
| link | `$title`, `$action` | POSTs to `$action` |
| message | `$heading`, `$message` | Says why a visitor can't go on |

`$title` is the host the visitor is going to. Every value comes HTML-escaped. The built-in pages load nothing from
anywhere; one of your own may, but no page can be framed.

## How it holds up

- **Cookies** are `HttpOnly` and `SameSite=Lax`, and over HTTPS `Secure` with the `__Host-` prefix: no script reads
  them and no other host receives them. Each is an HMAC under the lock's secret, for one host and one login.
- **Hand-off codes** work once, for one host, in the one browser that asked. The host keeps a secret in that browser and
  sends the home only its hash, so a code seen in a log or a history is no use elsewhere. The home hands codes only to
  hosts of the same tunnel, so a tunnel of someone else's under your wildcard never gets one. Redirects only go to a
  path on the host they came from.
- **Wrong passwords**, by form or header, count against the tunnel, not the address they came from: after
  `WILDBURROW_LOCK_ATTEMPTS` in a minute, password logins wait out the minute. Visitors already logged in carry on.
- Over plain HTTP, without `WILDBURROW_DNS`, cookies can't be `Secure`, and passwords cross the network as they're
  typed.
