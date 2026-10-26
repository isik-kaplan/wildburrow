"""Client settings saved in config.toml: below options, variables and answers, above the built-in defaults."""

import os
from typing import Any

import click
from isik.common.settings import Setting
from isik.common.settings.conversion import Invalid, convert
from isik.common.settings.resolution import display_default, walk

from wildburrow.cli.errors import Failure
from wildburrow.cli.output import table
from wildburrow.cli.settings import CLIENT_PREFIX, Tunnel
from wildburrow.client.config import LOGIN, config_path, read_toml, write_toml

FILE = "config.toml"
# Every client setting a variable can give, by the name it's saved under: its variable without the prefix.
SAVED = {
    entry.env_name.removeprefix(CLIENT_PREFIX).lower(): entry
    for entry in walk(Tunnel, {})
    if isinstance(entry.declaration, Setting) and entry.env_name
}


def _text(value: Any) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


def current() -> dict[str, str]:
    """What's saved, by variable, for the settings a login doesn't hold: those come in as the saved login."""
    saved = read_toml(config_path())
    return {SAVED[name].env_name: _text(value) for name, value in saved.items() if name in SAVED and name not in LOGIN}


def _named(name: str) -> tuple[str, Any]:
    key = name.replace("-", "_").lower()
    if key not in SAVED:
        raise Failure(f"no client setting is called {name}; `wildburrow config` lists them", 2)
    return key, SAVED[key]


@click.group("config", invoke_without_command=True)
@click.pass_context
def config(ctx: click.Context) -> int | None:
    """List every client setting, its value and where it comes from; or change what's saved."""
    return _config(ctx)


def _config(ctx: click.Context) -> int | None:
    if ctx.invoked_subcommand is None:
        return _list()
    return None


def _list() -> int:
    saved = read_toml(config_path())
    rows = [("NAME", "VALUE", "FROM")]
    for name, entry in SAVED.items():
        setting = entry.declaration
        if entry.env_name in os.environ:
            value, source = os.environ[entry.env_name], entry.env_name
        elif name in saved:
            value, source = _text(saved[name]), FILE
        else:
            value, source = display_default(setting) or "", "default"
        if setting.secret and source != "default":
            value = "(set)"
        rows.append((name, value or "-", source))
    table(rows)
    return 0


@config.command("set")
@click.argument("name")
@click.argument("value")
def set_setting(name: str, value: str) -> int:
    """Save VALUE for the client setting NAME, below its option and variable."""
    return _set(name, value)


def _set(name: str, value: str) -> int:
    key, entry = _named(name)
    try:
        typed = convert(entry.declaration, value)
    except Invalid as exc:
        raise Failure(f"{key}: {exc}, got {value!r}", 2) from None
    path = config_path()
    # A login's settings keep their types, as login writes them; the rest keep the text, as a variable would.
    write_toml(path, {**read_toml(path), key: typed if key in LOGIN else value})
    click.echo(f"saved {key} in {path}")
    return 0


@config.command("unset")
@click.argument("name")
def unset_setting(name: str) -> int:
    """Forget the saved value of the client setting NAME."""
    return _unset(name)


def _unset(name: str) -> int:
    key, _entry = _named(name)
    path = config_path()
    saved = read_toml(path)
    if key not in saved:
        click.echo(f"{key} isn't saved")
        return 0
    del saved[key]
    if saved:
        write_toml(path, saved)
    else:
        path.unlink()
    click.echo(f"forgot {key}")
    return 0
