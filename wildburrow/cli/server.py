import asyncio
import dataclasses
import getpass
import logging
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, get_type_hints

import click

from wildburrow import envfile
from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.config import FILE_SUFFIX, PREFIX, SECRET, SHOWN
from wildburrow.locks import LOCK_PREFIX, ServerLockSettings

SERVER_EXTRA = "the server needs extra dependencies: install 'wildburrow[server]'"
GROUPS = "wildburrow.settings"
ON_OFF = {True: "on", False: "off"}
SETTINGS_HELP = (
    f"Every setting is also an environment variable, --http-port as {PREFIX}HTTP_PORT. Add -file to an option, "
    f"or {FILE_SUFFIX} to a variable, to read the value from a file."
)


@dataclass(frozen=True, slots=True)
class SettingsGroup:
    title: str
    cls: type
    prefix: str

    def fields(self) -> Iterator[tuple[str, dataclasses.Field[Any]]]:
        for field in dataclasses.fields(self.cls):
            yield f"{self.prefix}{field.name.upper()}", field


def settings_groups() -> list[SettingsGroup]:
    try:
        from wildburrow import plugins
        from wildburrow.config import ServerSettings

        groups = [
            SettingsGroup("Server", ServerSettings, PREFIX),
            SettingsGroup("Locks", ServerLockSettings, LOCK_PREFIX),
        ]
        for kind in plugins.KINDS:
            for name, entry_point in sorted(plugins.available(kind).items()):
                groups.append(
                    SettingsGroup(f"{kind} plugin {name}", entry_point.load().Settings, plugins.prefix(kind, name))
                )
    except ImportError:
        raise Failure(SERVER_EXTRA, 2) from None
    return groups


def flag(var: str) -> str:
    return "--" + var.removeprefix(PREFIX).lower().replace("_", "-")


def shown(field: dataclasses.Field[Any]) -> str:
    if field.default is dataclasses.MISSING:
        return "required"
    value = field.metadata.get(SHOWN, field.default)
    if isinstance(value, bool):
        return f"default: {ON_OFF[value]}"
    return f"default: {','.join(value) if isinstance(value, tuple) else value}" if value != "" else "optional"


def _options(group: SettingsGroup, skip: frozenset[str]) -> Iterator[click.Option]:
    hints = get_type_hints(group.cls)
    for var, field in group.fields():
        if var in skip:
            continue
        name = flag(var)
        if hints[field.name] is bool:
            yield click.Option([f"{name}/--no-{name[2:]}", var], default=None, help=shown(field))
        else:
            yield click.Option([name, var], metavar=field.name.upper(), help=shown(field))
        yield click.Option([f"{name}-file", var + FILE_SUFFIX], hidden=True)


class SettingsCommand(click.Command):
    """Takes every server and plugin setting as an option, from the plugins installed when it runs."""

    skip: frozenset[str] = frozenset()

    def groups(self, ctx: click.Context) -> list[tuple[SettingsGroup, list[click.Option]]]:
        # Kept per run rather than on the command, which outlives a run wherever main is called more than once.
        if GROUPS not in ctx.meta:
            ctx.meta[GROUPS] = [(group, list(_options(group, self.skip))) for group in settings_groups()]
        return ctx.meta[GROUPS]

    def get_params(self, ctx: click.Context) -> list[click.Parameter]:
        return [*super().get_params(ctx), *(option for _, options in self.groups(ctx) for option in options)]

    def format_options(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        with formatter.section("Options"):
            formatter.write_dl([record for param in super().get_params(ctx) if (record := param.get_help_record(ctx))])
        for group, options in self.groups(ctx):
            with formatter.section(group.title):
                formatter.write_dl([record for option in options if (record := option.get_help_record(ctx))])


def given_settings(options: dict[str, Any]) -> dict[str, str]:
    """The settings among a command's options, as environment variables."""
    for var, value in options.items():
        if value is not None and options.get(var + FILE_SUFFIX) is not None:
            raise click.UsageError(f"{flag(var)} and {flag(var)}-file can't be used together")
    return {var: ON_OFF.get(value, value) for var, value in options.items() if value is not None}


def overlay(env: dict[str, str], settings: dict[str, str]) -> dict[str, str]:
    """`env` with `settings` replacing each setting in either of its forms."""
    merged = dict(env)
    for var, value in settings.items():
        setting = var.removesuffix(FILE_SUFFIX)
        merged.pop(setting, None)
        merged.pop(setting + FILE_SUFFIX, None)
        merged[var] = value
    return merged


@click.command(cls=SettingsCommand, epilog=SETTINGS_HELP)
@click.option(
    "--env-file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="read settings from KEY=VALUE lines, under the options and over the environment",
)
def serve(env_file: Path | None, **options: Any) -> int:
    """Run the server."""
    return _serve(env_file, options)


def _serve(env_file: Path | None, options: dict[str, Any]) -> int:
    from wildburrow.config import ConfigError
    from wildburrow.server import serve

    env = dict(os.environ)
    if env_file is not None:
        try:
            env = overlay(env, envfile.read(env_file))
        except envfile.EnvFileError as exc:
            raise Failure(f"configuration error: {exc}", 2) from None
    env = overlay(env, given_settings(options))
    if ask.interactive():
        env = _ask_missing(env)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        asyncio.run(serve(env))
    except ConfigError as exc:
        raise Failure(f"configuration error: {exc}", 2) from None
    except OSError as exc:
        raise Failure(f"could not start: {exc}") from None
    return 0


def _unset(group: SettingsGroup, env: dict[str, str]) -> Iterator[tuple[str, dataclasses.Field[Any]]]:
    for var, field in group.fields():
        if field.default is dataclasses.MISSING and var not in env and var + FILE_SUFFIX not in env:
            yield var, field


def _ask(env: dict[str, str], group: SettingsGroup) -> None:
    for var, field in _unset(group, env):
        question = ask.secret if field.metadata.get(SECRET) else ask.text
        env[var] = question(var, check=ask.required)


def _ask_missing(env: dict[str, str]) -> dict[str, str]:
    """`env` with every required setting it lacks asked for: the server's, then those of the plugins it picks."""
    from wildburrow import config, plugins

    env = dict(env)
    groups = {group.prefix: group for group in settings_groups()}
    _ask(env, groups[PREFIX])
    try:
        settings = config.load(config.ServerSettings, env, PREFIX)
    except config.ConfigError:
        return env
    # No DNS plugin is named "", so an unset one asks nothing.
    for kind, names in (("transport", settings.transports), ("auth", settings.auth), ("dns", (settings.dns,))):
        for name in names:
            if (group := groups.get(plugins.prefix(kind, name))) is not None:
                _ask(env, group)
    return env


@click.command("hash-password")
def hash_password() -> int:
    """Print an argon2 hash for the password auth plugin."""
    return _hash_password()


def _hash_password() -> int:
    try:
        from argon2 import PasswordHasher
    except ImportError:
        raise Failure(SERVER_EXTRA, 2) from None
    password = getpass.getpass("password: ")
    if password != getpass.getpass("again: "):
        raise Failure("passwords do not match")
    click.echo(PasswordHasher().hash(password))
    return 0
