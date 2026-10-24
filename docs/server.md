# Server

## As a service

```sh
uv tool install 'wildburrow[server]'
wildburrow service install
```

`service install` asks for the domain, whether to serve HTTPS and through which DNS provider, which keys may open
tunnels, and who may see and end others' sessions ([sessions.md](sessions.md)), then installs the server as a system
service and starts it: systemd on Linux, launchd on macOS. It asks for sudo itself. Point `tunnel.example.com` and
`*.tunnel.example.com` at the server; DNS wildcards match any depth, so deeper names resolve too.

```sh
wildburrow service status       # running or not, and where the logs are
wildburrow service edit         # the same questions, answered with the current settings
wildburrow service uninstall    # stop and remove it, asking whether to keep the certificates
```

Each takes the settings as options instead, and then asks nothing:

```sh
wildburrow service install --domain=tunnel.example.com --acme-email=you@example.com \
  --dns=cloudflare --dns-cloudflare-api-token-file=/root/cloudflare-token
wildburrow service edit --http-port=8080
wildburrow service uninstall --yes --purge
```

- Unless told otherwise, the service lets in the keys in your `~/.ssh/authorized_keys`, copied when you install or
  edit.
- Its settings live in `/etc/wildburrow`, readable only by root and the service.
- On Linux, an install under a home directory, which is where `uv tool install` puts it, runs as its owner with that
  home read-only; one outside any home, like `/opt`, runs as a throwaway user that systemd makes up. Either way it can
  bind ports 80 and 443 and nothing more. On macOS it runs as the install's owner, which macOS lets bind those ports.
- It refuses settings no one could log in with, such as token auth with only the ssh transport.

## HTTPS

Without a DNS provider the server serves plain HTTP on port 80. With one, it gets wildcard certificates by proving it
owns the domain through DNS-01:

- Port 80 redirects bound names to HTTPS, and port 443 terminates TLS, picking the certificate by SNI.
- A request whose `Host` isn't covered by the certificate of its connection gets `421`.
- Certificates for `*.<parent>` are issued the first time a name under that parent is bound, and renewed while in use.
- Try `--acme-directory=https://acme-staging-v02.api.letsencrypt.org/directory` until the first certificate comes
  through, so a mistake doesn't run into Let's Encrypt's rate limits.

## In the foreground

`wildburrow serve` runs the server with the same settings, read from options, an `--env-file` of `KEY=VALUE` lines, or
the environment:

```sh
sudo wildburrow serve --domain=tunnel.example.com
```

In a terminal it asks for any required setting still missing, such as the domain, or a DNS provider's token.

## Docker

```sh
docker run -d --restart unless-stopped -p 80:80 -p 443:443 -p 2222:2222 -v wildburrow-data:/data \
  -e WILDBURROW_DOMAIN=tunnel.example.com \
  -e WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" \
  -e WILDBURROW_DNS=cloudflare -e WILDBURROW_DNS_CLOUDFLARE_API_TOKEN=... \
  -e WILDBURROW_ACME_EMAIL=you@example.com \
  ghcr.io/isik-kaplan/wildburrow
```

- The image is tagged with each version and `latest`, for amd64 and arm64, and runs on Docker Desktop for macOS too.
- It runs as an unprivileged user and keeps its data in `/data`; a host file it reads must be readable by that user.
- [examples/docker-compose.traefik.yml](../examples/docker-compose.traefik.yml) runs it behind Traefik with TLS
  passthrough and PROXY protocol, for hosts where another proxy already owns ports 80 and 443.
- [examples/docker-compose.coolify.yml](../examples/docker-compose.coolify.yml) does the same as a Coolify Docker
  Compose application, behind Coolify's own Traefik.

## What clients are told

The server answers `GET /_wildburrow/info` on its own domain, or any host that isn't a tunnel's, with how to log in:

```json
{
  "version": "0.3.0",
  "transports": {"ssh": {"auth": ["key"], "port": 2222}, "websocket": {"auth": ["key", "token"]}},
  "defaults": {"transport": "ssh", "auth": "key"}
}
```

`wildburrow login` starts from it. Nothing secret is in it: no keys, hashes or token names.

- The default transport is the first in `WILDBURROW_TRANSPORTS` any auth method works over, and its auth method the
  first in `WILDBURROW_AUTH` order. `WILDBURROW_CLIENT_TRANSPORT` and `WILDBURROW_CLIENT_AUTH` choose them instead; one
  that can't log anyone in stops the server from starting.
- `WILDBURROW_SSH_PUBLIC_PORT` is the SSH port to publish when it differs from the one bound, as with `-p 2200:2222`.
