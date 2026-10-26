import asyncio
import dataclasses
import time
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any

import click
from isik.common.settings import UNSET, AskedAtUse, NoEnv, NoQuestion, ReplacedByFlow, Setting, Settings

from wildburrow import durations
from wildburrow.cli import ask, locking, saved, tokens
from wildburrow.cli.errors import Failure
from wildburrow.cli.output import table, when
from wildburrow.cli.settings import (
    ANY_USES,
    AUTH_METHODS,
    CLIENT_PREFIX,
    DEFAULTS,
    TRANSPORTS,
    Login,
    Remote,
    Tunnel,
    duration,
    never,
    options,
    use_limit,
)
from wildburrow.cli.tokens import DENY
from wildburrow.client import discovery, ssh, websocket
from wildburrow.client.config import ClientConfig, config_path, forget_login, read_config, write_config
from wildburrow.config import PREFIX

TOKEN_ENV = f"{CLIENT_PREFIX}TOKEN"
# Tokens only travel over websocket; ssh logs in with what ssh itself offers.
AUTH_BY_TRANSPORT = {"ssh": ("key", "password"), "websocket": tuple(AUTH_METHODS)}
BY_TOKEN = {"transport": "websocket", "auth": "token"}
# Set once connect has asked for its names, so its settings are asked for too; a port asked for always comes with them.
ASKED = "wildburrow.asked"
# Turns the sessions listed, and the server's reach, into what to end.
type Pick = Callable[[list[dict[str, Any]], dict[str, Any] | None], list[dict[str, str]]]
# What a command group was given, for its subcommands.
GROUP = "wildburrow.group"


def _given(options: dict[str, Any]) -> dict[str, Any]:
    return {name: value for name, value in options.items() if value is not None}


def _asked_port(ctx: click.Context, param: click.Parameter, value: int | None) -> int:
    if value is not None:
        return value
    if not ask.interactive():
        raise click.MissingParameter()
    return int(ask.text("Local port", "", ask.port))


def _asked_names(ctx: click.Context, param: click.Parameter, value: tuple[str, ...]) -> tuple[str, ...]:
    if value:
        return value
    if not ask.interactive():
        raise click.MissingParameter()
    ctx.meta[ASKED] = True
    return tuple(ask.text("Names, separated by spaces (* for any one label, as in *.myapp)", "", ask.required).split())


def _asking(given: object, no_input: bool) -> bool:
    """Questions follow only the ones for a port and names, so a tunnel given both opens without any."""
    return bool(click.get_current_context().meta.get(ASKED))


@options(Tunnel, interactive=_asking, current=saved.current)
@click.command()
@click.argument("port", type=click.IntRange(1, 65535), required=False, metavar="PORT", callback=_asked_port)
@click.argument("names", nargs=-1, metavar="NAME...", callback=_asked_names)
def connect(port: int, names: tuple[str, ...], settings: Tunnel) -> int:
    """Tunnel a local port (the default command): wildburrow 3000 myapp '*.foo'"""
    return _connect(port, names, settings)


def _connect(port: int, names: tuple[str, ...], settings: Tunnel) -> int:
    lock = locking.request(settings)
    config = reach(settings)
    index = None if settings.index is UNSET else settings.index
    if config.transport == "websocket":
        return websocket.run(config, port, list(names), settings.local_host, ask.password, lock, index)
    if lock is not None:
        raise Failure("a locked tunnel needs --transport websocket", 2)
    if index is not None:
        raise Failure("--index and --no-index need --transport websocket; an ssh tunnel takes the server's", 2)
    return ssh.run(config, port, list(names), settings.local_host, batch=ask.off())


def reach(settings: Remote) -> ClientConfig:
    """The saved login, with what this command, or the group it's in, was given in its place."""
    group = click.get_current_context().meta.get(GROUP)
    server = settings.server or (group.server if group else "")
    given = {**(group.connection.given() if group else {}), **settings.connection.given()}
    if given.get("token"):
        # A token says how to log in this time, whatever the saved login says.
        given = {**BY_TOKEN, **given}
    return dataclasses.replace(server_config(server or None), **given)


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


@options(Login, interactive=never)
@click.command()
@click.argument("server", required=False)
def login(server: str | None, settings: Login) -> int:
    """Save the server and how to connect to it. Asks for each, given no SERVER in a terminal."""
    return _login_given(server, settings.connection.given())


def _login_given(server: str | None, given: dict[str, Any]) -> int:
    return _login(server, given.pop("token", None), given)


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


@options(Remote, interactive=never, current=saved.current)
@click.command()
def names(settings: Remote) -> int:
    """List the names bound on the server right now, and which are yours. Logs in as a tunnel would."""
    return _names(reach(settings))


def _names(config: ClientConfig) -> int:
    held = _asked(websocket.held_names, config)
    if not held:
        click.echo("no names are bound")
        return 0
    rows = [(entry["name"], "you" if entry["yours"] else "someone else") for entry in held]
    table([("NAME", "HOLDER"), *sorted(rows)])
    return 0


def _asked[T](request: Callable[..., Awaitable[T]], config: ClientConfig, *args: Any) -> T:
    try:
        return asyncio.run(request(config, *args, ask.password))
    except websocket.ClientError as exc:
        raise Failure(str(exc)) from None


def _row(entry: dict[str, Any]) -> tuple[str, ...]:
    who = f"{entry['who']} (you)" if entry["yours"] else entry["who"]
    expires = "-" if entry["expires"] is None else when(entry["expires"])
    names = _listed(entry["names"]) or "-"
    return (entry["id"], who, f"{entry['via']}/{entry['transport']}", names, when(entry["since"]), expires,
            entry.get("from", "-"))  # fmt: skip


@options(Remote, interactive=never, current=saved.current)
@click.command()
def tunnels(settings: Remote) -> int:
    """List who is connected to the server, as far as you may see. Logs in as a tunnel would."""
    return _tunnels(reach(settings))


def _tunnels(config: ClientConfig) -> int:
    listed(config)
    return 0


def limited(reach: dict[str, Any] | None, level: str) -> str | None:
    """Why an admin reaches no one else, when the server keeps admins to their own sessions."""
    if reach is None or not reach["admin"] or reach[level] not in ("none", "own"):
        return None
    return f"this server keeps admins to their own sessions: {PREFIX}{level.upper()}={reach[level]}"


def listed(config: ClientConfig) -> list[dict[str, Any]]:
    """The sessions the server shows, after printing them."""
    found, reach = _asked(websocket.sessions, config)
    if not found:
        click.echo("no other sessions you can see")
        if hint := limited(reach, "see"):
            click.echo(hint, err=True)
        return found
    table([("ID", "WHO", "VIA", "NAMES", "SINCE", "EXPIRES", "FROM"), *map(_row, found)])
    return found


def pick_and_end(config: ClientConfig) -> int:
    """Lists the sessions, and ends the one picked from them."""
    found = listed(config)
    if not found or not ask.confirm("End one of them?", default=False):
        return 0
    choices = {entry["id"]: f"{entry['id']}: {who(entry)}" for entry in found}
    picked = ask.choose("Which?", choices, found[0]["id"])
    return end(config, lambda listed, reach: [{"session": picked}])


ONE_RUN = (
    "which sessions to end is this run's to say; one left in a variable would end them on every kick that reads it"
)
PICKED = ReplacedByFlow(
    flow=pick_and_end, reason="kick given nothing in a terminal lists the sessions and asks which one to end"
)


class Kick(Remote):
    who = Setting(
        str, "end every session of this identity, whatever else the word could mean; repeatable", default=(),
        multiple=True, metavar="IDENTITY", env=NoEnv(reason=ONE_RUN), question=PICKED,
    )  # fmt: skip
    name = Setting(
        str, "end whichever session holds this name, whatever else the word could mean; repeatable", default=(),
        multiple=True, metavar="NAME", env=NoEnv(reason=ONE_RUN), question=PICKED,
    )  # fmt: skip


def _readings(target: str, found: list[dict[str, Any]]) -> dict[str, list[str]]:
    """The ids of the sessions `target` names, by each thing it could be: a session id, an identity, a name held."""
    matches = {
        "session": [entry["id"] for entry in found if entry["id"] == target],
        "identity": [entry["id"] for entry in found if entry["who"] == target],
        "name": [entry["id"] for entry in found if target in entry["names"]],
    }
    return {kind: ids for kind, ids in matches.items() if ids}


def _targets(targets: tuple[str, ...], found: list[dict[str, Any]], reach: dict[str, Any] | None) -> list[str]:
    picked: dict[str, None] = {}
    for target in targets:
        readings = _readings(target, found)
        if not readings:
            hint = limited(reach, "see")
            raise Failure("\n".join(filter(None, [f"no session you can see matches {target}", hint])))
        if len({frozenset(ids) for ids in readings.values()}) > 1:
            lines = [f"  as {kind}: {_listed(ids)}" for kind, ids in readings.items()]
            pick = f"pass --who {target} or --name {target} to pick one"
            raise Failure("\n".join([f"{target} names different sessions:", *lines, pick]), 2)
        picked.update(dict.fromkeys(next(iter(readings.values()))))
    return list(picked)


@options(Kick, interactive=never, current=saved.current)
@click.command()
@click.argument("targets", nargs=-1, metavar="[TARGET]...")
def kick(targets: tuple[str, ...], settings: Kick) -> int:
    """End sessions on the server, each TARGET a session id from `wildburrow tunnels`, an identity or a name held."""
    return _kick(targets, settings)


def _kick(targets: tuple[str, ...], settings: Kick) -> int:
    if not (targets or settings.who or settings.name):
        if not ask.interactive():
            raise click.UsageError("pass TARGET, --who or --name")
        return pick_and_end(reach(settings))
    forced = [{"who": who} for who in settings.who] + [{"name": name} for name in settings.name]
    return end(
        reach(settings), lambda found, limits: [{"session": id} for id in _targets(targets, found, limits)] + forced
    )


def end(config: ClientConfig, pick: Pick) -> int:
    """Ends what `pick` makes of the sessions listed, saying what ended and how it could come back."""
    answer = _asked(websocket.kick, config, pick)
    for entry in answer["sessions"]:
        click.echo(f"ended {entry['id']}: {who(entry)}")
        if hint := _still_valid(entry):
            click.echo(f"  {hint}")
    for refused in answer["refused"]:
        click.echo(f"not allowed to end {refused}", err=True)
    if answer["refused"] and (hint := limited(answer["reach"], "kick")):
        click.echo(hint, err=True)
    if not answer["sessions"] and not answer["refused"]:
        click.echo("no session you can see matches", err=True)
        if hint := limited(answer["reach"], "see"):
            click.echo(hint, err=True)
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


class Logout(Settings, prefix=CLIENT_PREFIX):
    yes = Setting(
        bool, "don't ask first", option=("-y", "--yes"), default=False, negatable=False,
        env=NoEnv(reason="forgetting the login is this run's to decide; a variable would skip the question for good"),
        question=AskedAtUse(reason="the question names the saved server, so it's asked once that's been read"),
    )  # fmt: skip


@options(Logout, interactive=never)
@click.command()
def logout(settings: Logout) -> int:
    """Forget the saved server."""
    return _logout(settings.yes)


def _logout(yes: bool) -> int:
    path = config_path()
    saved = read_config(path)
    if saved is None:
        click.echo("not logged in")
        return 0
    if not yes and ask.interactive() and not ask.confirm(f"Forget {saved.server}?"):
        return 1
    forget_login(path)
    click.echo(f"forgot {saved.server}")
    return 0


@options(Remote, interactive=never, current=saved.current)
@click.group(invoke_without_command=True)
@click.pass_context
def links(ctx: click.Context, settings: Remote) -> int | None:
    """List who may get into your locked tunnels, and who has; add or end their links and passwords."""
    return _links_group(ctx, settings)


def _links_group(ctx: click.Context, settings: Remote) -> int | None:
    if ctx.invoked_subcommand is None:
        return _links(reach(settings))
    ctx.meta[GROUP] = settings
    return None


ADDED = "a link is one person's way in; a variable would give every link it mints the same"
SAID = NoQuestion(reason="links add takes what it needs on its command line, and the link it prints is all it does")


class LinkAdd(Remote):
    label = Setting(
        str, "label it, as your app is told who logged in", option="--as", default=UNSET, shown="the next link-N",
        metavar="LABEL", env=NoEnv(reason=f"{ADDED} label, which the server refuses"), question=SAID,
    )  # fmt: skip
    expires = Setting(
        duration, "stop it working after this long", default=UNSET, shown="with the tunnel", metavar="DURATION",
        env=NoEnv(reason=f"{ADDED} expiry, without anyone choosing it for that link"), question=SAID,
    )  # fmt: skip
    uses = Setting(
        use_limit, "how often it works: a number, or any for no limit", default=1, metavar="N|any",
        env=NoEnv(reason=f"{ADDED} limit, without anyone choosing it for that link"), question=SAID,
    )  # fmt: skip


@options(LinkAdd, interactive=never, current=saved.current)
@links.command("add")
@click.argument("url")
def add_link(url: str, settings: LinkAdd) -> int:
    """Make one more one-time link to a locked tunnel of yours, landing on URL."""
    return _add_link(url, settings)


def _add_link(url: str, settings: LinkAdd) -> int:
    label = None if settings.label is UNSET else settings.label
    request: dict[str, Any] = {"url": url, "label": label, "uses": settings.uses}
    if settings.expires is not UNSET:
        request["expires"] = int(time.time()) + durations.seconds(settings.expires)
    answer = _asked(websocket.link, reach(settings), request)
    if "error" in answer:
        raise Failure(str(answer["error"]))
    click.echo(f"{answer['label']}  {answer['url']}")
    return 0


@options(Remote, interactive=never, current=saved.current)
@links.command("end")
@click.argument("whos", nargs=-1, required=True, metavar="WHO...")
def end_links(whos: tuple[str, ...], settings: Remote) -> int:
    """End passwords or links, by the WHO `wildburrow links` lists, logging out whoever used them."""
    return _end_links(whos, settings)


def _end_links(whos: tuple[str, ...], settings: Remote) -> int:
    missing = []
    for answer in _asked(websocket.end_logins, reach(settings), whos):
        for names in answer["ended"]:
            click.echo(f"ended {answer['who']} on {_listed(names)}")
        if not answer["ended"]:
            missing.append(answer["who"])
    if missing:
        raise Failure(f"no password or link named {_listed(missing)} in your locked tunnels")
    return 0


def _spent(entry: dict[str, Any]) -> tuple[int, int | None]:
    """How often a link has been used and may be; a server before 0.5.0 says only when one single-use link was."""
    return entry.get("spent", int(entry["used"] is not None)), entry.get("uses", 1)


def _state(entry: dict[str, Any]) -> str:
    if entry["ended"]:
        return "ended"
    if entry["kind"] == "password":
        return "open"
    spent, uses = _spent(entry)
    if uses is not None and spent >= uses:
        return "used up"
    if entry["expires"] is not None and entry["expires"] <= time.time():
        return "expired"
    return "open"


def _uses(entry: dict[str, Any]) -> str:
    if entry["kind"] == "password":
        return "-"
    spent, uses = _spent(entry)
    return f"{spent}/{ANY_USES if uses is None else uses}"


def _login_row(entry: dict[str, Any]) -> tuple[str, ...]:
    """One password's or link's line in `links`."""
    seen = "-" if entry["seen"] is None else when(entry["seen"])
    expires = "-" if entry["expires"] is None else when(entry["expires"])
    return entry["who"], entry["kind"], _state(entry), _uses(entry), str(entry["logins"]), seen, expires


def _links(config: ClientConfig) -> int:
    found = _asked(websocket.logins, config)
    if not found:
        click.echo("no locked tunnels of yours")
    for index, tunnel in enumerate(found):
        if index:
            click.echo()
        click.echo(_listed(tunnel["names"]))
        rows = [_login_row(entry) for entry in tunnel["logins"]]
        table([("WHO", "KIND", "STATE", "USES", "LOGINS", "LAST SEEN", "EXPIRES"), *rows])
    return 0


@options(Remote, interactive=never, current=saved.current)
@tokens.tokens_group.command("deny")
@click.argument("ids", nargs=-1, required=True, metavar="ID...")
def deny_tokens(ids: tuple[str, ...], settings: Remote) -> int:
    """Stop tokens logging in, by the ID `tokens` lists, ending their sessions now; for an admin of the server."""
    return _deny_tokens(ids, settings)


def _deny_tokens(ids: tuple[str, ...], settings: Remote) -> int:
    answer = _asked(websocket.deny, reach(settings), ids)
    if "error" in answer:
        raise Failure(str(answer["error"]))
    for token in answer["tokens"]:
        click.echo(f"denied {token}")
    if answer["ended"]:
        click.echo(f"ended {len(answer['ended'])} of their sessions")
    return 0
