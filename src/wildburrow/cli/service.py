import asyncio
import dataclasses
import os
import pwd
import shutil
import sys
from pathlib import Path
from typing import Any

import click

from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.cli.server import (
    SettingsCommand,
    SettingsGroup,
    given_settings,
    overlay,
    settings_groups,
)
from wildburrow.config import FILE_SUFFIX, PREFIX, SECRET
from wildburrow.core.names import LABEL
from wildburrow.service import (
    DATA_DIR,
    ENV_PATH,
    NAME,
    Config,
    Manager,
    ServiceError,
    install_account,
)
from wildburrow.service import manager as find_manager

DOMAIN = f"{PREFIX}DOMAIN"
DNS = f"{PREFIX}DNS"
ACME_EMAIL = f"{PREFIX}ACME_EMAIL"
TRANSPORTS = f"{PREFIX}TRANSPORTS"
AUTH = f"{PREFIX}AUTH"
KEYS = f"{PREFIX}AUTH_KEY_AUTHORIZED_KEYS"
AUTHORIZED_KEYS = Path(".ssh/authorized_keys")
TRANSPORT_CHOICES = {
    "ssh": "ssh: clients connect on port 2222",
    "ssh,websocket": "ssh, and websocket on port 443 for clients behind proxies or firewalls",
}


def _manager() -> Manager:
    try:
        return find_manager()
    except ServiceError as exc:
        raise Failure(str(exc)) from None


def _as_root() -> None:
    if os.geteuid() == 0:
        return
    if shutil.which("sudo") is None:
        raise Failure("this needs root")
    click.echo("this needs root; asking sudo", err=True)
    os.execvp("sudo", ["sudo", sys.executable, "-m", NAME, *sys.argv[1:]])  # noqa: S606, S607


def _home() -> Path:
    """The home of whoever asked for the change, not root's when they went through sudo."""
    if os.geteuid() == 0 and (user := os.environ.get("SUDO_USER")):
        return Path(pwd.getpwnam(user).pw_dir)
    return Path.home()


def _key_lines(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))


def _domain(answer: str) -> str | None:
    labels = answer.strip().lower().split(".")
    return None if len(labels) > 1 and all(LABEL.fullmatch(label) for label in labels) else "not a domain name"


def _keys_file(answer: str) -> str | None:
    path = Path(answer.strip()).expanduser()
    if not path.is_file():
        return "no such file"
    return None if _key_lines(path.read_text()) else "no keys in that file"


def _dns_groups() -> dict[str, SettingsGroup]:
    from wildburrow import plugins

    groups = {group.prefix: group for group in settings_groups()}
    return {name: groups[plugins.prefix("dns", name)] for name in sorted(plugins.available("dns"))}


def _ask_dns(settings: dict[str, str], current: dict[str, str]) -> None:
    groups = _dns_groups()
    choices = {"": "none: plain HTTP on port 80"}
    choices |= {name: f"{name}: HTTPS, proving the domain through {name}" for name in groups}
    dns = ask.choose("Certificates", choices, current.get(DNS, ""))
    for var in [var for var in settings if any(var.startswith(group.prefix) for group in groups.values())]:
        del settings[var]
    settings.pop(ACME_EMAIL, None)
    settings.pop(DNS, None)
    if not dns:
        return
    settings[DNS] = dns
    for var, field in groups[dns].fields():
        if field.default is not dataclasses.MISSING:
            continue
        label = field.name.replace("_", " ")
        if field.metadata.get(SECRET):
            kept = " (empty keeps the current one)" if var in current else ""
            settings[var] = ask.secret(f"{dns} {label}{kept}", None if kept else _required) or current[var]
        else:
            settings[var] = ask.text(f"{dns} {label}", current.get(var, ""), _required)
    if email := ask.text("E-mail for the certificate authority (optional)", current.get(ACME_EMAIL, "")):
        settings[ACME_EMAIL] = email


def _required(answer: str) -> str | None:
    return None if answer.strip() else "required"


def _ask_keys(settings: dict[str, str], current: dict[str, str], home: Path) -> None:
    if "key" not in settings.get(AUTH, "key").split(","):
        return
    if KEYS in current:
        if ask.confirm(f"Keep the {_key_lines(current[KEYS])} keys allowed to open tunnels?"):
            return
    else:
        click.echo("Keys allowed to open tunnels:")
    path = ask.text("An authorized_keys file to copy them from", str(home / AUTHORIZED_KEYS), _keys_file)
    settings[KEYS] = Path(path).expanduser().read_text().strip()


def _ask_settings(current: dict[str, str], home: Path) -> dict[str, str]:
    settings = dict(current)
    settings[DOMAIN] = ask.text("Domain the tunnels live under", current.get(DOMAIN, ""), _domain).lower()
    _ask_dns(settings, current)
    transports = current.get(TRANSPORTS, "ssh")
    settings[TRANSPORTS] = ask.choose("Transports", {transports: transports} | TRANSPORT_CHOICES, transports)
    _ask_keys(settings, current, home)
    return settings


def _secrets() -> set[str]:
    return {var for group in settings_groups() for var, field in group.fields() if field.metadata.get(SECRET)}


def _summary(settings: dict[str, str]) -> None:
    hidden = _secrets()
    for var, value in settings.items():
        shown = "(hidden)" if var in hidden else f"({_key_lines(value)} keys)" if var == KEYS else value
        click.echo(f"  {var.removeprefix(PREFIX).lower()}: {shown}")


def _prepare(settings: dict[str, str], home: Path) -> dict[str, str]:
    """`settings` made whole: files read in, the invoker's keys by default, and checked the way serve checks."""
    resolved = {}
    for var, value in settings.items():
        if var.endswith(FILE_SUFFIX):
            try:
                resolved[var.removesuffix(FILE_SUFFIX)] = Path(value).expanduser().read_text().strip()
            except OSError as exc:
                raise Failure(f"{var}: {exc}", 2) from None
        else:
            resolved[var] = value
    if "key" in resolved.get(AUTH, "key").split(","):
        if KEYS not in resolved:
            path = home / AUTHORIZED_KEYS
            if not path.is_file():
                raise Failure(f"no keys to let in: {path} doesn't exist; pass --auth-key-authorized-keys-file", 2)
            resolved[KEYS] = path.read_text().strip()
        # The service has no home of its own to fall back on, so it always gets its keys spelled out.
        if not _key_lines(resolved[KEYS]):
            raise Failure("no keys to let in: the authorized keys given hold none", 2)
    _check(resolved)
    return resolved


def _check(settings: dict[str, str]) -> None:
    from wildburrow import config
    from wildburrow.server import Server

    try:
        server = Server(config.load(config.ServerSettings, settings, PREFIX), settings)
    except config.ConfigError as exc:
        raise Failure(f"configuration error: {exc}", 2) from None
    if server.dns is not None:
        asyncio.run(server.dns.aclose())


def _settings(given: dict[str, str], current: dict[str, str], action: str) -> dict[str, str]:
    home = _home()
    if given:
        settings = overlay(current, given)
    elif ask.interactive():
        settings = _ask_settings(current, home)
    else:
        raise Failure(f"no settings given: pass them as options, or run `wildburrow service {action}` in a terminal", 2)
    settings = _prepare(settings, home)
    if not given:
        _summary(settings)
        if not ask.confirm("Save these and start the server?"):
            raise click.Abort
    return settings


def _report(manager: Manager) -> None:
    click.echo(f"{NAME} is {manager.status()} as a {manager.kind} service")
    click.echo(f"  settings: {ENV_PATH} (change them with `wildburrow service edit`)")
    click.echo(f"  logs: {manager.logs()}")


@click.group()
def service() -> None:
    """Run the server as a system service: systemd on Linux, launchd on macOS."""


class _ServiceSettings(SettingsCommand):
    # A service keeps its data where its service manager says.
    skip = frozenset({DATA_DIR})


SERVICE_SETTINGS = {
    "cls": _ServiceSettings,
    "epilog": "Add -file to an option to read the value from a file; the service keeps its own copy.",
}


@service.command(**SERVICE_SETTINGS)
@click.option("--force", is_flag=True, help="replace an existing install")
def install(force: bool, **options: Any) -> int:
    """Install the server as a service and start it. Asks for each setting, given none in a terminal."""
    manager = _manager()
    _as_root()
    if manager.installed() and not force:
        raise Failure("already installed: change it with `wildburrow service edit`, or pass --force")
    settings = _settings(given_settings(options), {}, "install")
    if manager.installed():
        manager.uninstall()
    account = install_account()
    Config(manager).save(settings, account)
    manager.install(account)
    _report(manager)
    return 0


@service.command(**SERVICE_SETTINGS)
def edit(**options: Any) -> int:
    """Change the service's settings and restart it. Asks for each, given none in a terminal."""
    manager = _manager()
    _as_root()
    if not manager.installed():
        raise Failure("not installed: run `wildburrow service install`")
    config = Config(manager)
    config.save(_settings(given_settings(options), config.load(), "edit"), install_account())
    manager.restart()
    _report(manager)
    return 0


@service.command()
@click.option("--purge", is_flag=True, help="also delete the certificates, ACME account and SSH host key")
@click.option("--yes", "-y", is_flag=True, help="don't ask first")
def uninstall(purge: bool, yes: bool) -> int:
    """Stop the service and remove it."""
    manager = _manager()
    _as_root()
    if not manager.installed():
        click.echo("not installed")
        return 0
    if not yes:
        if not ask.interactive():
            raise Failure("pass --yes to uninstall without being asked", 2)
        if not ask.confirm(f"Stop and remove the {NAME} service?", default=False):
            return 1
        purge = purge or ask.confirm("Also delete its certificates, ACME account and SSH host key?", default=False)
    manager.uninstall()
    Config(manager).remove()
    if purge:
        for directory in manager.data_dirs():
            shutil.rmtree(directory, ignore_errors=True)
    click.echo(f"removed the {NAME} service" + (" and its data" if purge else ""))
    return 0


@service.command()
def status() -> int:
    """Show whether the service runs, and where its settings and logs are."""
    manager = _manager()
    if not manager.installed():
        click.echo("not installed")
        return 1
    _report(manager)
    return 0
