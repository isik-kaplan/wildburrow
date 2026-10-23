# wildburrow docs

Each page covers one part: what it does, how to use it, and what to know.

## Using it

- [client.md](client.md) - installing the client, `login` and `logout`, the two transports, how a tunnel stays up,
  proxies, and plain `ssh`
- [names.md](names.md) - names and wildcards at any depth, which one a request reaches, binding a tunnel's names all
  or none, `wildburrow names`, and several local sites behind one router
- [tokens.md](tokens.md) - signed tokens to let people in without an SSH key on the server: minting, scoping by name,
  expiry, and ending them early
- [sessions.md](sessions.md) - who is connected, `wildburrow tunnels` and `kick`, tunnels ending with their token, and
  who may see and end whose sessions

## Running a server

- [server.md](server.md) - `service install` on systemd and launchd, HTTPS through DNS-01, running in the foreground,
  Docker and Traefik, and what the server tells clients about logging in
- [settings.md](settings.md) - every setting, as an option, an environment variable, a `_FILE` variable or an
  `--env-file` line

## Extending and working on it

- [plugins.md](plugins.md) - transports, auth methods and DNS providers as entry point plugins
- [development.md](development.md) - running the tests, the mutation runs, and how releases happen

What changed in each release: [CHANGELOG.md](../CHANGELOG.md).
