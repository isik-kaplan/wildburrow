import asyncio
import dataclasses
import math
import os
import time
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any

import click

from wildburrow import durations
from wildburrow.cli import ask, locking
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
BY_TOKEN = {"transport": "websocket", "auth": "token"}


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
        *locking.OPTIONS,
    ]
)
@click.argument("port", type=click.IntRange(1, 65535))
@click.argument("names", nargs=-1, required=True, metavar="NAME...")
def connect(port: int, names: tuple[str, ...], server: str | None, local_host: str, **options: Any) -> int:
    """Tunnel a local port (the default command): wildburrow 3000 myapp '*.foo'"""
    return _connect(port, names, server, local_host, options)


def _connect(port: int, names: tuple[str, ...], server: str | None, local_host: str, options: dict[str, Any]) -> int:
    lock = locking.request({key: value for key, value in options.items() if key in locking.NAMES})
    given = _given({key: value for key, value in options.items() if key not in locking.NAMES})
    config = dataclasses.replace(server_config(server), **given)
    if config.transport == "websocket":
        return websocket.run(config, port, list(names), local_host, ask.password, lock)
    if lock is not None:
        raise Failure("--lock and --link need --transport websocket", 2)
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
        # A token in the environment is how to log in this time, whatever the saved login says.
        config = dataclasses.replace(config, token=token, **BY_TOKEN)
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
        transport, auth = given["transport"], given["auth"]
        if auth not in AUTH_BY_TRANSPORT[transport]:
            offered = _listed(AUTH_BY_TRANSPORT[transport])
            raise Failure(f"{auth} logins don't go over {transport}, which takes: {offered}", 2)
        return config
    published = _published(config)
    if published is None:
        return config
    transport = given.get("transport") or _carrying(published, given.get("auth"))
    if transport not in published.auth:
        raise Failure(f"{config.server} doesn't take --transport {transport}; it offers: {_listed(published.auth)}", 2)
    auth = given.get("auth", published.method_for(transport))
    if auth not in published.auth[transport]:
        offered = _listed(published.auth[transport])
        raise Failure(f"{config.server} doesn't take --auth {auth} over {transport}; it takes: {offered}", 2)
    port = given.get("ssh_port", published.ssh_port or config.ssh_port)
    return dataclasses.replace(config, transport=transport, auth=auth, ssh_port=port)


def _carrying(published: discovery.Published, auth: str | None) -> str:
    """The transport the server suggests, unless only another one takes the method given."""
    transports = [published.transport, *published.auth]
    return next((name for name in transports if auth in published.auth[name]), published.transport)


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


@click.command(params=[click.Option(["--token"], help="token to log in with; means --auth token"), *CLIENT_OPTIONS])
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
        given = _given(options)
        if token is not None:
            # A token says how to log in, so the method the server suggests doesn't replace it.
            given = {"auth": BY_TOKEN["auth"], **given}
        config = _resolve(ClientConfig(server, **_given({"token": token}), **given), given)
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


@click.command("link")
@click.argument("url")
@click.option("--as", "label", help="label it, as your app is told who logged in (default: the next link-N)")
@click.option("--expires", metavar="DURATION", help="stop it working after this long (default: with the tunnel)")
@click.option("--server", help="server to ask instead of the saved one")
def link(url: str, label: str | None, expires: str | None, server: str | None) -> int:
    """Make one more one-time link to a locked tunnel of yours, landing on URL."""
    return _link(url, label, expires, server)


def _link(url: str, label: str | None, expires: str | None, server: str | None) -> int:
    request: dict[str, Any] = {"url": url, "label": label}
    if expires is not None:
        if (length := durations.seconds(expires)) is None:
            raise Failure(f"--expires: expected a duration {durations.EXAMPLES}, got {expires!r}", 2)
        request["expires"] = int(time.time()) + length
    answer = _asked(websocket.link, server, request)
    if "error" in answer:
        raise Failure(str(answer["error"]))
    click.echo(f"{answer['label']}  {answer['url']}")
    return 0


@click.command()
@click.option("--end", "who", metavar="WHO", help="end this password or link, logging out whoever used it")
@click.option("--server", help="server to ask instead of the saved one")
def links(who: str | None, server: str | None) -> int:
    """List who may get into your locked tunnels, and who has. Logs in as a tunnel would."""
    return _links(who, server)


def _status(entry: dict[str, Any]) -> str:
    if entry["ended"]:
        return "ended"
    if entry["kind"] == "password":
        return f"{entry['logins']} login{'' if entry['logins'] == 1 else 's'}" if entry["logins"] else "-"
    if entry["used"] is not None:
        return f"used {when(entry['used'])}"
    if entry["expires"] is not None and entry["expires"] <= time.time():
        return "expired"
    return "unused" if entry["expires"] is None else f"unused, until {when(entry['expires'])}"


def _links(who: str | None, server: str | None) -> int:
    if who is not None:
        answer = _asked(websocket.end_login, server, who)
        for names in answer["ended"]:
            click.echo(f"ended {who} on {_listed(names)}")
        if not answer["ended"]:
            raise Failure(f"no password or link named {who} in your locked tunnels")
        return 0
    found = _asked(websocket.logins, server)
    if not found:
        click.echo("no locked tunnels of yours")
    for index, tunnel in enumerate(found):
        if index:
            click.echo()
        click.echo(_listed(tunnel["names"]))
        rows = [
            (entry["who"], entry["kind"], _status(entry), "-" if entry["seen"] is None else when(entry["seen"]))
            for entry in tunnel["logins"]
        ]
        table([("WHO", "KIND", "USED", "LAST SEEN"), *rows])
    return 0
