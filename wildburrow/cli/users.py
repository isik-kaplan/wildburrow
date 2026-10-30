"""The server's users, for its admins, and joining it with an invite."""

import asyncio
import getpass
from pathlib import Path
from typing import Any

import click
from isik.common.settings import UNSET, NoEnv, NoQuestion, Setting, Settings

from wildburrow import durations
from wildburrow.cli import client, saved
from wildburrow.cli.errors import Failure
from wildburrow.cli.output import table, when
from wildburrow.cli.settings import CLIENT_PREFIX, Remote, duration, never, options
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, write_config

# Said whenever the server would forget what an admin just changed.
MEMORY = (
    "warning: the server keeps its database in memory, so this is lost when it stops; set WILDBURROW_DATABASE to a "
    "file on the server to keep it"
)
ONE_INVITE = NoEnv(reason="an invite is for one person, which a variable would make the same for everyone")
ON_THE_LINE = NoQuestion(reason="said on the command line, by the admin or the invite's own instructions")
SOURCES = {"settings": "settings", "token": "token", "database": "invited"}


@options(Remote, interactive=never, current=saved.current)
@click.group("users", invoke_without_command=True)
@click.pass_context
def users_group(ctx: click.Context, settings: Remote) -> int | None:
    """List the server's users, or invite and manage them; for an admin."""
    return _users_group(ctx, settings)


def _users_group(ctx: click.Context, settings: Remote) -> int | None:
    if ctx.invoked_subcommand is None:
        return _list(client.reach(settings))
    ctx.meta[client.GROUP] = settings
    return None


def _answered(request: Any, config: ClientConfig, *args: Any) -> dict[str, Any]:
    answer: dict[str, Any] = client._asked(request, config, *args)
    if "error" in answer:
        raise Failure(str(answer["error"]))
    if answer.get("memory"):
        click.echo(MEMORY, err=True)
    return answer


def _logins(user: dict[str, Any]) -> str:
    found = (["password"] if user["password"] else []) + [f"key ({label})" for label in user["keys"]]
    if user["invited_until"] is not None:
        found.append(f"invited until {when(user['invited_until'])}")
    return ", ".join(found) or "-"


def _list(config: ClientConfig) -> int:
    answer = _answered(websocket.users, config)
    rows = [
        (
            user["name"], user["alias"] or "-", SOURCES[user["source"]], "yes" if user["admin"] else "no",
            "removed" if user["gone"] else _logins(user),
        )
        for user in answer["users"]
    ]  # fmt: skip
    table([("USER", "ALIAS", "FROM", "ADMIN", "LOGS IN WITH"), *rows])
    return 0


class Invite(Remote):
    expires = Setting(
        duration, "how long the invite can wait to be used", default="7d", metavar="DURATION", env=ONE_INVITE,
        question=ON_THE_LINE,
    )  # fmt: skip


@options(Invite, interactive=never, current=saved.current)
@users_group.command("invite")
@click.argument("name")
def invite(name: str, settings: Invite) -> int:
    """Invite NAME to the server.

    Prints a one-time code they set up their own password or key with, by `wildburrow join`.
    """
    return _invite(name, settings)


def _invite(name: str, settings: Invite) -> int:
    config = client.reach(settings)
    answer = _answered(websocket.invite, config, name, durations.seconds(settings.expires))
    click.echo(f"invited {answer['name']}, until {when(answer['expires'])}; they run:")
    click.echo(f"  wildburrow join {config.server} {answer['code']}")
    return 0


@options(Remote, interactive=never, current=saved.current)
@users_group.command("promote")
@click.argument("name")
def promote(name: str, settings: Remote) -> int:
    """Make an invited user an admin."""
    return _set_admin(name, True, settings)


@options(Remote, interactive=never, current=saved.current)
@users_group.command("demote")
@click.argument("name")
def demote(name: str, settings: Remote) -> int:
    """Make an invited user no longer an admin.

    Admins the server's settings make stay admins: only the settings change them.
    """
    return _set_admin(name, False, settings)


def _set_admin(name: str, admin: bool, settings: Remote) -> int:
    answer = _answered(websocket.set_admin, client.reach(settings), name, admin)
    state = "an admin" if admin else "not an admin"
    click.echo(f"{name} is {state}" if answer["changed"] else f"{name} was already {state}")
    if answer["still"]:
        click.echo(f"{name} is still an admin by the server's WILDBURROW_ADMINS, which only its settings change")
    return 0


@options(Remote, interactive=never, current=saved.current)
@users_group.command("remove")
@click.argument("name")
def remove(name: str, settings: Remote) -> int:
    """Stop an invited user logging in.

    Ends their sessions, and their password, keys and open invite; their history stays.
    """
    return _remove(name, settings)


def _remove(name: str, settings: Remote) -> int:
    answer = _answered(websocket.remove_user, client.reach(settings), name)
    click.echo(f"removed {name}")
    if answer["ended"]:
        click.echo(f"ended {len(answer['ended'])} of their sessions")
    return 0


class Join(Settings, prefix=CLIENT_PREFIX):
    key = Setting(
        str, "log in with this SSH key too: the private key's path", default=UNSET, shown="no key", metavar="PATH",
        env=ONE_INVITE, question=ON_THE_LINE,
    )  # fmt: skip
    password = Setting(
        bool, "set a password, asked twice", default=True, env=ONE_INVITE, question=ON_THE_LINE,
    )  # fmt: skip
    alias = Setting(
        str, "a second name to log in with", default=UNSET, shown="none", metavar="NAME", env=ONE_INVITE,
        question=ON_THE_LINE,
    )  # fmt: skip
    device = Setting(
        str, "what the key is on, as admins see it", default=UNSET, shown="the key's comment", metavar="NAME",
        env=ONE_INVITE, question=ON_THE_LINE,
    )  # fmt: skip


@options(Join, interactive=never)
@click.command("join")
@click.argument("server")
@click.argument("code")
def join(server: str, code: str, settings: Join) -> int:
    """Join SERVER with the CODE an admin invited you with.

    Sets up your password, your key or both, and saves the login as `wildburrow login` does.
    """
    return _join(server, code, settings)


def _join(server: str, code: str, settings: Join) -> int:
    if not settings.password and settings.key is UNSET:
        raise Failure("joining sets a password, a key, or both: drop --no-password, or pass --key", 2)
    request: dict[str, Any] = {"code": code}
    if settings.key is not UNSET:
        # Beside the private key, as ssh-keygen puts it: the whole name and .pub, so my.key's is my.key.pub.
        public = Path(f"{Path(settings.key).expanduser()}.pub")
        try:
            request["public_key"] = public.read_text().strip()
        except OSError as exc:
            raise Failure(f"can't read {public}: {exc.strerror}") from None
        if settings.device is not UNSET:
            request["label"] = settings.device
    if settings.alias is not UNSET:
        request["alias"] = settings.alias
    if settings.password:
        password = getpass.getpass("password: ")
        if password != getpass.getpass("again: "):
            raise Failure("passwords do not match")
        request["password"] = password
    config = ClientConfig(server, transport="websocket")
    try:
        name = asyncio.run(websocket.join(config, request))
    except websocket.ClientError as exc:
        raise Failure(str(exc)) from None
    auth = "password" if settings.password else "key"
    identity = "" if settings.key is UNSET else settings.key
    saved_login = ClientConfig(server, user=name, transport="websocket", auth=auth, identity=identity)
    write_config(config_path(), saved_login)
    click.echo(f"joined {server} as {name}; saved {config_path()}")
    return 0
