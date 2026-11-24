import asyncio
import dataclasses
import json
import os
import time
from pathlib import Path
from typing import Any

import click
from isik.common.settings import UNSET, AskedAtUse, NoEnv, NoQuestion, ReplacedByFlow, Setting, Settings

from wildburrow import durations, tokens
from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.cli.output import NEVER, table, when
from wildburrow.cli.settings import CLIENT_PREFIX, never, options
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, read_config
from wildburrow.config import PREFIX
from wildburrow.core.names import ANY, InvalidName, parse_patterns
from wildburrow.durations import UNITS

DEFAULT_EXPIRY = "7d"
DURATIONS = "30m, 12h, 7d, 2w or never"
SERVER_PLACEHOLDER = "SERVER"


def log_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "wildburrow" / "tokens.jsonl"


def _expiry(raw: str, now: int) -> int | None:
    if raw.strip().lower() == NEVER:
        return None
    if (length := durations.seconds(raw)) is None:
        raise Failure(f"--expires: expected a count and one of {', '.join(UNITS)} (like 7d or 12h), or {NEVER}", 2)
    return now + length


def _scope(names: tuple[str, ...] | None) -> str:
    return "any name" if names is None else ", ".join(names)


def _warning(grant: tokens.Grant) -> str:
    until = "that never expires" if grant.expires is None else f"until {when(grant.expires)}"
    return (
        f"{grant.name} gets a token for {_scope(grant.names)} {until}.\n"
        "Only an admin denying it, or its name, stops it sooner."
    )


def _confirmed(grant: tokens.Grant, yes: bool) -> bool:
    if yes:
        return True
    if not ask.interactive():
        raise Failure("pass --yes to mint a token without being asked; only a denial stops it once it's out", 2)
    click.echo(_warning(grant))
    return ask.confirm("Mint it?", default=False)


def _entries() -> list[dict[str, Any]]:
    path = log_path()
    return [json.loads(line) for line in path.read_text().splitlines() if line] if path.exists() else []


def _record(grant: tokens.Grant, server: str, registered: bool | None) -> None:
    path = log_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry = {
        "id": grant.id, "name": grant.name, "names": grant.names, "expires": grant.expires, "issued": grant.issued,
        "server": server, "registered": registered,
    }  # fmt: skip
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as log:
        log.write(json.dumps(entry) + "\n")


def _registered(ids: set[str]) -> None:
    """Marks `ids` registered in the log, rewritten whole beside it and swapped in."""
    path = log_path()
    entries = _entries()
    # A token just minted is registered before it's written down, and written down as registered.
    if not ids & {entry["id"] for entry in entries}:
        return
    entries = [entry | {"registered": True} if entry["id"] in ids else entry for entry in entries]
    temporary = path.with_name(f".{path.name}.new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as log:
        log.write("".join(json.dumps(entry) + "\n" for entry in entries))
    os.replace(temporary, path)


def unsynced(server: str | None = None) -> list[dict[str, Any]]:
    """Tokens minted here with --offline, or whose registering failed, on `server` or any; older mints never are."""
    return [
        entry for entry in _entries()
        if entry.get("registered") is False and (server is None or entry["server"] == server)
    ]  # fmt: skip


def _grant(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: entry[key] for key in ("id", "name", "names", "expires", "issued")}


def _talk(config: ClientConfig, grants: list[dict[str, Any]], listing: bool) -> dict[str, Any]:
    """Registers `grants` and maybe lists, marking what got registered; the answer, or {"error": why}."""
    try:
        answer = asyncio.run(websocket.tokens(config, grants, listing, ask.password))
    except websocket.ClientError as exc:
        return {"error": str(exc), "registered": []}
    if answer["registered"]:
        _registered(set(answer["registered"]))
    if answer.get("memory"):
        click.echo(f"{config.server} keeps its record in memory, so it forgets registered tokens on restart", err=True)
    return answer


def ask_token() -> int:
    """Asks who a token is for, what it may claim and for how long, and mints it."""
    name = ask.text("Who is it for", "", ask.required)
    names = ask.text(f"Names they may claim, comma-separated (or {ANY})", f"{name},*.{name}", ask.required)
    expires = ask.text(f"Good for ({DURATIONS})", DEFAULT_EXPIRY, ask.required)
    return _token(name, names, expires, None, None, False, False, False)


ASKED = ReplacedByFlow(flow=ask_token, reason="tokens new given no NAME in a terminal asks for the name first")


class Mint(
    Settings,
    prefix=CLIENT_PREFIX,
    env=NoEnv(reason="a token is minted once, for one person; a variable would give every token minted the same"),
):
    names = Setting(
        str, f"names it may claim, comma-separated with * for any one label, or {ANY}", default=UNSET,
        shown="", question=ASKED,
    )  # fmt: skip
    expires = Setting(str, f"like 30m, 12h, 7d or 2w, or {NEVER}", default=DEFAULT_EXPIRY, question=ASKED)
    identity = Setting(
        str, "SSH key to sign with", default=UNSET, shown="the saved login's, else the first in ~/.ssh",
        question=NoQuestion(reason="the saved login's key signs, nearly always the one; --identity covers the rest"),
    )  # fmt: skip
    server = Setting(
        str, "server to register it with and log in to", default=UNSET, shown="the saved login's",
        question=NoQuestion(reason="the saved login names the server, and the line printed says when there is none"),
    )  # fmt: skip
    yes = Setting(
        bool, "don't ask first", option=("-y", "--yes"), default=False, negatable=False,
        question=AskedAtUse(reason="the warning and its question come once the grant is known, just before signing"),
    )  # fmt: skip
    offline = Setting(
        bool, "don't register it with the server, which then lists it only once it's used", default=False,
        negatable=False,
        question=AskedAtUse(reason="asked as whether to mint it anyway, once registering it with the server fails"),
    )  # fmt: skip
    hashed = Setting(
        bool, "a random token for the server's TOKEN_HASHES instead", option="--hash", default=False,
        negatable=False, question=NoQuestion(reason="a hashed token is the rarer kind, for servers without signers"),
    )  # fmt: skip


@click.group("tokens", invoke_without_command=True)
@click.pass_context
def tokens_group(ctx: click.Context) -> int | None:
    """List the tokens the saved login's server has and those minted here; or mint one with `tokens new`."""
    return _tokens_group(ctx)


def _tokens_group(ctx: click.Context) -> int | None:
    if ctx.invoked_subcommand is None:
        return _list_tokens()
    return None


def _given(settings: Settings, name: str) -> str | None:
    value = getattr(settings, name)
    return None if value is UNSET else value


@options(Mint, interactive=never)
@tokens_group.command("new")
@click.argument("name", required=False)
def new_token(name: str | None, settings: Mint) -> int:
    """Mint a token signed with your SSH key, for a server that trusts the key in AUTH_TOKEN_SIGNERS."""
    return _new_token(name, settings)


def _new_token(name: str | None, settings: Mint) -> int:
    if name is None:
        if not ask.interactive():
            raise click.MissingParameter(param_type="argument", param_hint="'NAME'")
        return ask_token()
    return _token(
        name, _given(settings, "names"), settings.expires, _given(settings, "identity"), _given(settings, "server"),
        settings.yes, settings.hashed, settings.offline,
    )  # fmt: skip


def _token(
    name: str,
    names: str | None,
    expires: str,
    identity: str | None,
    server: str | None,
    yes: bool,
    hashed: bool,
    offline: bool,
) -> int:
    if hashed:
        value = tokens.new_token()
        click.echo(f"token (give this to the client): {value}")
        click.echo(f"server line (add to {PREFIX}AUTH_TOKEN_HASHES): {name}:{tokens.digest(value)}")
        return 0
    if names is None:
        raise Failure(f"pass --names: the names {name} may claim, or {ANY}", 2)
    try:
        patterns = parse_patterns(names)
    except InvalidName as exc:
        raise Failure(f"--names: {exc}", 2) from None
    now = int(time.time())
    grant = tokens.Grant(name, patterns, _expiry(expires, now), now, tokens.new_id())
    if not _confirmed(grant, yes):
        return 1
    saved = read_config(config_path()) or ClientConfig("")
    try:
        key = websocket.identity_file(identity or saved.identity)
        armored = websocket.sign(key, tokens.NAMESPACE, grant.payload())
    except websocket.ClientError as exc:
        raise Failure(str(exc)) from None
    value = tokens.encode(grant.payload(), tokens.unarmor(armored))
    target = server or saved.server
    registered = False if offline else _register(grant, target)
    if registered is None:
        return 1
    # With no server named, there's nothing it could be registered with later either.
    _record(grant, target, registered if target else None)
    click.echo(f"token for {name}, valid until {when(grant.expires)}, for: {_scope(patterns)}")
    click.echo(f"id: {grant.id} (`wildburrow tokens deny {grant.id}` stops it early)")
    click.echo(f"\non {name}'s device:")
    click.echo("  uv tool install wildburrow")
    # --auth spelled out for clients before 0.4.1, which take the server's suggested method over a given token.
    click.echo(f"  wildburrow login {target or SERVER_PLACEHOLDER} --auth token --token {value}")
    if not target:
        click.echo(f"\nno saved login to name the server: replace {SERVER_PLACEHOLDER}, or pass --server", err=True)
    return 0


def _register(grant: tokens.Grant, server: str) -> bool | None:
    """
    Registers `grant` with `server`: True once it is; False when it couldn't be and minting it anyway was asked
    for; None when it wasn't.
    """
    config = read_config(config_path())
    if config is None or not server:
        problem = "no saved login to reach a server with"
    else:
        answer = _talk(dataclasses.replace(config, server=server), [_entry(grant)], listing=False)
        if "error" not in answer:
            return True
        problem = str(answer["error"])
    where = server or "a server"
    if not ask.interactive():
        raise Failure(f"couldn't register the token with {where}: {problem}; pass --offline", 2)
    click.echo(f"Couldn't register the token with {where}: {problem}")
    if not ask.confirm("Mint it without registering it?", default=False):
        return None
    return False


def _entry(grant: tokens.Grant) -> dict[str, Any]:
    return {"id": grant.id, "name": grant.name, "names": grant.names, "expires": grant.expires, "issued": grant.issued}


def _list_tokens() -> int:
    config = read_config(config_path())
    found: dict[str, Any] = {"tokens": [], "denied_names": {}}
    if config is not None:
        answer = _talk(config, [_grant(entry) for entry in unsynced(config.server)], listing=True)
        if "error" in answer:
            click.echo(f"couldn't list {config.server}'s tokens: {answer['error']}; listing this machine's", err=True)
        else:
            found = answer
            for row in found["tokens"]:
                row["server"] = config.server
    # Read after registering, which marks what it registered.
    local = {entry["id"]: entry for entry in _entries()}
    listed = {row["id"]: row for row in found["tokens"]}
    for token, entry in local.items():
        # What the server knows of a token wins over what was written here when it was minted.
        listed[token] = entry | {key: value for key, value in listed.get(token, {}).items() if value is not None}
    if not listed:
        click.echo("no tokens")
        return 0
    now = time.time()
    rows = [("ID", "NAME", "NAMES", "EXPIRES", "LAST USED", "STATE", "SERVER")]
    for token, entry in listed.items():
        expires = entry["expires"]
        expiry = when(expires) if expires is None or expires > now else f"expired {when(expires)}"
        names = None if entry["names"] is None else tuple(entry["names"])
        last = when(entry["last_used"]) if entry.get("last_used") else "-"
        rows.append(
            (
                token,
                entry["name"] or "-",
                _scope(names),
                expiry,
                last,
                _state(entry, found, config),
                entry["server"] or "-",
            )
        )
    table(rows)
    for name, before in found["denied_names"].items():
        click.echo(f"denied: every token for {name} minted before {when(before)}")
    return 0


def _state(entry: dict[str, Any], found: dict[str, Any], config: ClientConfig | None) -> str:
    # A name denied on the saved login's server says nothing of tokens for another.
    mine = config is not None and entry["server"] == config.server
    before = found["denied_names"].get(entry["name"]) if mine else None
    if entry.get("denied") or (before is not None and entry.get("issued") is not None and entry["issued"] < before):
        return "denied"
    if entry.get("registered") is False:
        return "unregistered"
    return "-"


@tokens_group.command("sync")
def sync_tokens() -> int:
    """Register the tokens minted here with --offline with the saved login's server, so any admin can list them."""
    return _sync()


def _sync() -> int:
    config = read_config(config_path())
    if config is None:
        raise Failure("no saved login to reach a server with: run `wildburrow login` first", 2)
    waiting = unsynced(config.server)
    if not waiting:
        click.echo(f"every token minted here for {config.server} is registered")
        return 0
    answer = _talk(config, [_grant(entry) for entry in waiting], listing=False)
    if answer["registered"]:
        click.echo(f"registered {len(answer['registered'])} of {len(waiting)} with {config.server}")
    if "error" in answer:
        raise Failure(f"couldn't register with {config.server}: {answer['error']}")
    return 0
