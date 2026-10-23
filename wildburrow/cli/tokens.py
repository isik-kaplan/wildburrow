import json
import os
import re
import time
from pathlib import Path
from typing import Any

import click

from wildburrow import tokens
from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.cli.output import NEVER, table, when
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, read_config
from wildburrow.config import PREFIX
from wildburrow.core.names import ANY, InvalidName, parse_patterns

DEFAULT_EXPIRY = "7d"
UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
DURATION = re.compile(r"([1-9][0-9]*)([mhdw])")
DENY = f"{PREFIX}AUTH_TOKEN_DENY"
SERVER_PLACEHOLDER = "SERVER"


def log_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "wildburrow" / "tokens.jsonl"


def _expiry(raw: str, now: int) -> int | None:
    if raw.strip().lower() == NEVER:
        return None
    if not (match := DURATION.fullmatch(raw.strip().lower())):
        raise Failure(f"--expires: expected a count and one of {', '.join(UNITS)} (like 7d or 12h), or {NEVER}", 2)
    return now + int(match[1]) * UNITS[match[2]]


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


@click.command()
@click.argument("name")
@click.option("--names", help=f"names it may claim, comma-separated with * for any one label, or {ANY}")
@click.option("--expires", default=DEFAULT_EXPIRY, show_default=True, help=f"like 30m, 12h, 7d or 2w, or {NEVER}")
@click.option("--identity", help="SSH key to sign with (default: the saved login's, else the first in ~/.ssh)")
@click.option("--server", help="server for the login line (default: the saved login's)")
@click.option("--yes", "-y", is_flag=True, help="don't ask first")
@click.option("--hash", "hashed", is_flag=True, help="a random token for the server's TOKEN_HASHES instead")
def token(
    name: str, names: str | None, expires: str, identity: str | None, server: str | None, yes: bool, hashed: bool
) -> int:
    """Mint a token signed with your SSH key, for a server that trusts the key in AUTH_TOKEN_SIGNERS."""
    return _token(name, names, expires, identity, server, yes, hashed)


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
    click.echo(f"  wildburrow login {target or SERVER_PLACEHOLDER} --token {value}")
    if not target:
        click.echo(f"\nno saved login to name the server: replace {SERVER_PLACEHOLDER}, or pass --server", err=True)
    return 0


@click.command("tokens")
def list_tokens() -> int:
    """List the tokens minted on this machine; a server can't list them."""
    return _list_tokens()


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
