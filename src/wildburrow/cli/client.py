import dataclasses
import math
import os
from pathlib import Path
from typing import Any

import click

from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.client import ssh, websocket
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
    saved = read_config(config_path())
    server = server or (saved and saved.server)
    if not server:
        raise Failure("no server configured: run `wildburrow login` or pass --server", 2)
    overrides = _given(options)
    if token := os.environ.get(TOKEN_ENV):
        overrides["token"] = token
    config = dataclasses.replace(saved, server=server, **overrides) if saved else ClientConfig(server, **overrides)
    run = websocket.run if config.transport == "websocket" else ssh.run
    return run(config, port, list(names), local_host)


def _required(answer: str) -> str | None:
    return None if answer.strip() else "required"


def _port(answer: str) -> str | None:
    return None if answer.isdigit() else "a port number"


def _key_file(answer: str) -> str | None:
    if not answer.strip() or Path(answer.strip()).expanduser().is_file():
        return None
    return "no such file"


def _default_identity(saved: ClientConfig) -> str:
    if saved.identity:
        return saved.identity
    try:
        return str(websocket.identity_file(saved))
    except websocket.ClientError:
        return ""


def _ask_login(saved: ClientConfig) -> ClientConfig:
    server = ask.text("Server", saved.server, _required)
    transport = ask.choose("Connect over", TRANSPORTS, saved.transport)
    methods = {method: AUTH_METHODS[method] for method in AUTH_BY_TRANSPORT[transport]}
    auth = ask.choose("Log in with", methods, saved.auth if saved.auth in methods else "key")
    config = dataclasses.replace(saved, server=server, transport=transport, auth=auth)
    if transport == "ssh":
        port = ask.text("SSH port", str(saved.ssh_port), _port)
        config = dataclasses.replace(config, ssh_port=int(port))
    if auth == "key":
        identity = ask.text("SSH key (empty lets ssh pick)", _default_identity(saved), _key_file)
        config = dataclasses.replace(config, identity=identity)
    if auth == "token":
        config = dataclasses.replace(config, token=ask.secret("Token", _required))
    return config


@click.command(params=[click.Option(["--token"], help="token for the token auth method"), *CLIENT_OPTIONS])
@click.argument("server", required=False)
def login(server: str | None, token: str | None, **options: Any) -> int:
    """Save the server and how to connect to it. Asks for each, given no SERVER in a terminal."""
    path = config_path()
    if server is None and token is None and not _given(options):
        if not ask.interactive():
            raise Failure("missing SERVER: pass it, or run `wildburrow login` in a terminal to be asked", 2)
        config = _ask_login(read_config(path) or DEFAULTS)
    elif server is None:
        raise click.UsageError("Missing argument 'SERVER'.")
    else:
        config = ClientConfig(server, **_given({"token": token, **options}))
    write_config(path, config)
    click.echo(f"saved {path}")
    return 0


@click.command()
@click.option("--yes", "-y", is_flag=True, help="don't ask first")
def logout(yes: bool) -> int:
    """Forget the saved server."""
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
