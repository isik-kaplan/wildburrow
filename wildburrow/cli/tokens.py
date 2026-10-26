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
DENY = f"{PREFIX}AUTH_TOKEN_DENY"
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
    if grant.expires is None:
        return (
            f"{grant.name} gets a token for {_scope(grant.names)} that never expires.\n"
            f"Only rotating the signer key or adding its id to {DENY} will ever stop it."
        )
    return (
        f"{grant.name} gets a token for {_scope(grant.names)} until {when(grant.expires)}.\n"
        "It can't be withdrawn before then, short of rotating the signer key."
    )


def _confirmed(grant: tokens.Grant, yes: bool) -> bool:
    if yes:
        return True
    if not ask.interactive():
        raise Failure("pass --yes to mint a token without being asked; it can't be withdrawn once minted", 2)
    click.echo(_warning(grant))
    return ask.confirm("Mint it?", default=False)


def _record(grant: tokens.Grant, server: str) -> None:
    path = log_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry = {"id": grant.id, "name": grant.name, "names": grant.names, "expires": grant.expires, "server": server}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as log:
        log.write(json.dumps(entry) + "\n")


def ask_token() -> int:
    """Asks who a token is for, what it may claim and for how long, and mints it."""
    name = ask.text("Who is it for", "", ask.required)
    names = ask.text(f"Names they may claim, comma-separated (or {ANY})", f"{name},*.{name}", ask.required)
    expires = ask.text(f"Good for ({DURATIONS})", DEFAULT_EXPIRY, ask.required)
    return _token(name, names, expires, None, None, False, False)


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
        str, "server for the login line", default=UNSET, shown="the saved login's",
        question=NoQuestion(reason="the saved login names the server, and the line printed says when there is none"),
    )  # fmt: skip
    yes = Setting(
        bool, "don't ask first", option=("-y", "--yes"), default=False, negatable=False,
        question=AskedAtUse(reason="the warning and its question come once the grant is known, just before signing"),
    )  # fmt: skip
    hashed = Setting(
        bool, "a random token for the server's TOKEN_HASHES instead", option="--hash", default=False,
        negatable=False, question=NoQuestion(reason="a hashed token is the rarer kind, for servers without signers"),
    )  # fmt: skip


@click.group("tokens", invoke_without_command=True)
@click.pass_context
def tokens_group(ctx: click.Context) -> int | None:
    """List the tokens minted on this machine, which a server can't list; or mint one with `tokens new`."""
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
        settings.yes, settings.hashed,
    )  # fmt: skip


def _token(
    name: str, names: str | None, expires: str, identity: str | None, server: str | None, yes: bool, hashed: bool
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
    _record(grant, target)
    click.echo(f"token for {name}, valid until {when(grant.expires)}, for: {_scope(patterns)}")
    click.echo(f"id: {grant.id} (for {DENY}, should it need stopping early)")
    click.echo(f"\non {name}'s device:")
    click.echo("  uv tool install wildburrow")
    # --auth spelled out for clients before 0.4.1, which take the server's suggested method over a given token.
    click.echo(f"  wildburrow login {target or SERVER_PLACEHOLDER} --auth token --token {value}")
    if not target:
        click.echo(f"\nno saved login to name the server: replace {SERVER_PLACEHOLDER}, or pass --server", err=True)
    return 0


def _list_tokens() -> int:
    path = log_path()
    entries: list[dict[str, Any]] = (
        [json.loads(line) for line in path.read_text().splitlines() if line] if path.exists() else []
    )
    if not entries:
        click.echo("no tokens minted on this machine")
        return 0
    now = time.time()
    rows = [("ID", "NAME", "NAMES", "EXPIRES", "SERVER")]
    for entry in entries:
        expires = entry["expires"]
        state = when(expires) if expires is None or expires > now else f"expired {when(expires)}"
        names = None if entry["names"] is None else tuple(entry["names"])
        rows.append((entry["id"], entry["name"], _scope(names), state, entry["server"] or "-"))
    table(rows)
    return 0
