import asyncio
import dataclasses
import math
import os
import time
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any

import click

from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.cli.output import table, when
from wildburrow.cli.tokens import DENY
from wildburrow.client import discovery, ssh, websocket
from wildburrow.client.config import ClientConfig, config_path, read_config, write_config
from wildburrow.config import PREFIX

TOKEN_ENV = f"{PREFIX}TOKEN"
DEFAULTS = ClientConfig("")
ON_OFF = {True: "on", False: "off"}
TRANSPORTS = {
    "ssh": "ssh: your ssh binary, on port 2222",
    "websocket": "websocket: wss:// on port 443, which gets through most proxies and firewalls",
}
AUTH_METHODS = {
    "key": "key: your SSH key",
    "password": "password: asked each time you connect",
    "token": "token: one made with `wildburrow token NAME` on the server",
}
# Tokens only travel over websocket; ssh logs in with what ssh itself offers.
AUTH_BY_TRANSPORT = {"ssh": ("key", "password"), "websocket": tuple(AUTH_METHODS)}


class _Seconds(click.ParamType):
    name = "seconds"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> float:
        try:
            seconds = float(value)
        except ValueError:
            self.fail(f"expected a number of seconds, got {value!r}")
        if not 0 < seconds < math.inf:
            self.fail(f"expected a positive number of seconds, got {value!r}")
        return seconds


CLIENT_OPTIONS = (
    click.Option(["--ssh-port"], type=int, help=f"(default: {DEFAULTS.ssh_port})"),
    click.Option(["--user"], help="SSH user (default: your local user)"),
    click.Option(["--transport"], type=click.Choice(list(TRANSPORTS)), help=f"(default: {DEFAULTS.transport})"),
    click.Option(["--auth"], type=click.Choice(list(AUTH_METHODS)), help=f"(default: {DEFAULTS.auth})"),
    click.Option(["--identity"], help="SSH key for websocket"),
    click.Option(["--url"], help="websocket base URL override"),
    click.Option(
        ["--reconnect/--no-reconnect"],
        default=None,
        help=f"reconnect when the connection drops (default: {ON_OFF[DEFAULTS.reconnect]})",
    ),
    click.Option(
        ["--retry-delay"],
        type=_Seconds(),
        metavar="SECONDS",
        help=f"first wait before reconnecting, doubled after each failure (default: {DEFAULTS.retry_delay:g})",
    ),
    click.Option(
        ["--retry-max"],
        type=_Seconds(),
        metavar="SECONDS",
        help=f"longest wait between reconnects (default: {DEFAULTS.retry_max:g})",
    ),
)


def _given(options: dict[str, Any]) -> dict[str, Any]:
    return {name: value for name, value in options.items() if value is not None}


@click.command(
    params=[
        click.Option(["--server"], help="server to use instead of the saved one"),
        click.Option(["--local-host"], default="localhost", show_default=True, help="where the local port listens"),
        *CLIENT_OPTIONS,
    ]
)
@click.argument("port", type=click.IntRange(1, 65535))
@click.argument("names", nargs=-1, required=True, metavar="NAME...")
def connect(port: int, names: tuple[str, ...], server: str | None, local_host: str, **options: Any) -> int:
    """Tunnel a local port (the default command): wildburrow 3000 myapp '*.foo'"""
    return _connect(port, names, server, local_host, options)


def _connect(port: int, names: tuple[str, ...], server: str | None, local_host: str, options: dict[str, Any]) -> int:
    config = dataclasses.replace(server_config(server), **_given(options))
    if config.transport == "websocket":
        return websocket.run(config, port, list(names), local_host, ask.password)
    return ssh.run(config, port, list(names), local_host, batch=ask.off())


def server_config(server: str | None) -> ClientConfig:
    """The saved login, on `server` if given; in a terminal with none saved, logging in first."""
    saved = read_config(config_path())
    if not server and not saved:
        if not ask.interactive():
            raise Failure("no server configured: run `wildburrow login` or pass --server", 2)
        click.echo("Not logged in to a server yet.")
        _login(None, None, {})
        saved = read_config(config_path())
    if saved is None:
        assert server is not None  # noqa: S101
        config = ClientConfig(server)
    else:
        config = dataclasses.replace(saved, server=server or saved.server)
    if token := os.environ.get(TOKEN_ENV):
        config = dataclasses.replace(config, token=token)
    return config


def _key_file(answer: str) -> str | None:
    if not answer.strip() or Path(answer.strip()).expanduser().is_file():
        return None
    return "no such file"


def _default_identity(saved: ClientConfig) -> str:
    if saved.identity:
        return saved.identity
    try:
        return str(websocket.default_identity())
    except websocket.ClientError:
        return ""


def _published(config: ClientConfig) -> discovery.Published | None:
    published = discovery.fetch(config.url or f"https://{config.server}", AUTH_BY_TRANSPORT)
    if published is None:
        click.echo(f"{config.server} doesn't say how to log in; starting from the built-in defaults", err=True)
    return published


def _listed(names: Iterable[str]) -> str:
    return ", ".join(names)


def _resolve(config: ClientConfig, given: dict[str, Any]) -> ClientConfig:
    """`config` with what the server publishes filling in whatever wasn't given."""
    if "transport" in given and "auth" in given:
        return config
    published = _published(config)
    if published is None:
        return config
    transport = given.get("transport", published.transport)
    if transport not in published.auth:
        raise Failure(f"{config.server} doesn't take --transport {transport}; it offers: {_listed(published.auth)}", 2)
    auth = given.get("auth", published.method_for(transport))
    if auth not in published.auth[transport]:
        offered = _listed(published.auth[transport])
        raise Failure(f"{config.server} doesn't take --auth {auth} over {transport}; it takes: {offered}", 2)
    port = given.get("ssh_port", published.ssh_port or config.ssh_port)
    return dataclasses.replace(config, transport=transport, auth=auth, ssh_port=port)


def _pick(question: str, choices: dict[str, str], default: str) -> str:
    if len(choices) > 1:
        return ask.choose(question, choices, default)
    [only] = choices
    click.echo(f"{question}: {only}, the only one the server offers")
    return only


def _ask_login(saved: ClientConfig) -> ClientConfig:
    server = ask.text("Server", saved.server, ask.required)
    published = _published(dataclasses.replace(saved, server=server))
    if published is None:
        offered, mine = AUTH_BY_TRANSPORT, True
    else:
        # A choice made for this server before stands; for another server, its own default does.
        offered, mine = published.auth, server == saved.server
    choices = {name: TRANSPORTS[name] for name in offered}
    transport = _pick(
        "Connect over", choices, saved.transport if mine and saved.transport in offered else published.transport
    )
    methods = {method: AUTH_METHODS[method] for method in offered[transport]}
    if mine and saved.auth in methods:
        default = saved.auth
    else:
        default = "key" if published is None else published.method_for(transport)
    auth = _pick("Log in with", methods, default)
    config = dataclasses.replace(saved, server=server, transport=transport, auth=auth)
    if transport == "ssh":
        port = published.ssh_port if published and published.ssh_port else saved.ssh_port
        config = dataclasses.replace(config, ssh_port=int(ask.text("SSH port", str(port), ask.port)))
    if auth == "key":
        identity = ask.text("SSH key (empty lets ssh pick)", _default_identity(saved), _key_file)
        config = dataclasses.replace(config, identity=identity)
    if auth == "token":
        config = dataclasses.replace(config, token=ask.secret("Token", ask.required))
    return config


@click.command(params=[click.Option(["--token"], help="token for the token auth method"), *CLIENT_OPTIONS])
@click.argument("server", required=False)
def login(server: str | None, token: str | None, **options: Any) -> int:
    """Save the server and how to connect to it. Asks for each, given no SERVER in a terminal."""
    return _login(server, token, options)


def _login(server: str | None, token: str | None, options: dict[str, Any]) -> int:
    path = config_path()
    if server is None and token is None and not _given(options):
        if not ask.interactive():
            raise Failure("missing SERVER: pass it, or run `wildburrow login` in a terminal to be asked", 2)
        config = _ask_login(read_config(path) or DEFAULTS)
    elif server is None:
        raise click.UsageError("Missing argument 'SERVER'.")
    else:
        config = _resolve(ClientConfig(server, **_given({"token": token, **options})), _given(options))
        if config.auth == "token" and not config.token:
            click.echo(f"no token saved: pass --token, or set {TOKEN_ENV} when connecting", err=True)
    write_config(path, config)
    click.echo(f"saved {path}")
    return 0


@click.command()
@click.option("--server", help="server to ask instead of the saved one")
def names(server: str | None) -> int:
    """List the names bound on the server right now, and which are yours. Logs in as a tunnel would."""
    return _names(server)


def _names(server: str | None) -> int:
    held = _asked(websocket.held_names, server)
    if not held:
        click.echo("no names are bound")
        return 0
    rows = [(entry["name"], "you" if entry["yours"] else "someone else") for entry in held]
    table([("NAME", "HOLDER"), *sorted(rows)])
    return 0


def _asked[T](request: Callable[..., Awaitable[T]], server: str | None, *args: Any) -> T:
    try:
        return asyncio.run(request(server_config(server), *args, ask.password))
    except websocket.ClientError as exc:
        raise Failure(str(exc)) from None


def _row(entry: dict[str, Any]) -> tuple[str, ...]:
    who = f"{entry['who']} (you)" if entry["yours"] else entry["who"]
    expires = "-" if entry["expires"] is None else when(entry["expires"])
    names = _listed(entry["names"]) or "-"
    return (entry["id"], who, f"{entry['via']}/{entry['transport']}", names, when(entry["since"]), expires,
            entry.get("from", "-"))  # fmt: skip


@click.command()
@click.option("--server", help="server to ask instead of the saved one")
def tunnels(server: str | None) -> int:
    """List who is connected to the server, as far as you may see. Logs in as a tunnel would."""
    return _tunnels(server)


def _tunnels(server: str | None) -> int:
    listed(server)
    return 0


def listed(server: str | None) -> list[dict[str, Any]]:
    """The sessions the server shows, after printing them."""
    found = _asked(websocket.sessions, server)
    if not found:
        click.echo("no other sessions you can see")
        return found
    table([("ID", "WHO", "VIA", "NAMES", "SINCE", "EXPIRES", "FROM"), *map(_row, found)])
    return found


@click.command()
@click.argument("session", required=False)
@click.option("--name", help="end whichever session holds this name")
@click.option("--who", help="end every session of this identity")
@click.option("--server", help="server to ask instead of the saved one")
def kick(session: str | None, name: str | None, who: str | None, server: str | None) -> int:
    """End sessions on the server: by id from `wildburrow tunnels`, by a name held, or by identity."""
    return _kick(session, name, who, server)


def _kick(session: str | None, name: str | None, who: str | None, server: str | None) -> int:
    picked = {key: value for key, value in {"session": session, "name": name, "who": who}.items() if value}
    if len(picked) != 1:
        raise click.UsageError("pass one of SESSION, --name and --who")
    return end(server, picked)


def end(server: str | None, picked: dict[str, str]) -> int:
    """Ends what `picked` names, saying what ended and how it could come back."""
    answer = _asked(websocket.kick, server, picked)
    for entry in answer["sessions"]:
        click.echo(f"ended {entry['id']}: {who(entry)}")
        if hint := _still_valid(entry):
            click.echo(f"  {hint}")
    for refused in answer["refused"]:
        click.echo(f"not allowed to end {refused}", err=True)
    if not answer["sessions"] and not answer["refused"]:
        click.echo("no session you can see matches", err=True)
    return 0 if answer["sessions"] and not answer["refused"] else 1


def who(entry: dict[str, Any]) -> str:
    names = _listed(entry["names"]) or "no names"
    return f"{entry['who']} over {entry['transport']}, holding {names}"


def _still_valid(entry: dict[str, Any]) -> str | None:
    """How whoever was ended can come back, unless it was this identity's own session."""
    if entry["yours"]:
        return None
    if not entry["token"]:
        return f"{entry['who']} can connect again with the same {entry['via']}"
    expires = entry["expires"]
    if expires is not None and expires <= time.time():
        return None
    until = "for good" if expires is None else f"until {when(expires)}"
    return f"their token {entry['token']} logs in {until}; to stop it sooner, add the id to {DENY}"


@click.command()
@click.option("--yes", "-y", is_flag=True, help="don't ask first")
def logout(yes: bool) -> int:
    """Forget the saved server."""
    return _logout(yes)


def _logout(yes: bool) -> int:
    path = config_path()
    saved = read_config(path)
    if saved is None:
        click.echo("not logged in")
        return 0
    if not yes and ask.interactive() and not ask.confirm(f"Forget {saved.server}?"):
        return 1
    path.unlink()
    click.echo(f"removed {path}")
    return 0
