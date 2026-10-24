"""`--lock` and `--link`, from the command line or the environment, turned into the lock the client asks for."""

import itertools
import os
import secrets
import time
from pathlib import Path
from typing import Any

import click

from wildburrow import config, durations
from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.client.locking import LockRequest
from wildburrow.config import PREFIX
from wildburrow.locks import (
    DEFAULTS,
    FIELDS,
    GUEST,
    LABEL,
    LOCK_PREFIX,
    PAGES,
    PASSWORD_BYTES,
    LockSettings,
    merged,
    next_links,
    problems,
)

LOCK_ENV = f"{PREFIX}LOCK"
LINK_ENV = f"{PREFIX}LINK"
LINK_EXPIRES_ENV = f"{PREFIX}LINK_EXPIRES"
# What a bare --lock or --link stands for.
BARE = ""
SERVERS = "(default: the server's)"
FILE = click.Path(exists=True, dir_okay=False, path_type=Path)
LABELS = "1-64 letters, digits and . _ @ -"


def flag(name: str) -> str:
    return "--lock-" + name.replace("_", "-")


OPTIONS = (
    click.Option(
        ["--lock"],
        multiple=True,
        is_flag=False,
        flag_value=BARE,
        metavar="[USER[:PASSWORD]]",
        help="let USER in with PASSWORD, asked for or made up when left out; alone, makes up both; repeatable",
    ),
    click.Option(
        ["--link"],
        multiple=True,
        is_flag=False,
        flag_value=BARE,
        metavar="[N|LABELS]",
        help="one-time links: one alone, N of them, or one per comma-separated label; repeatable",
    ),
    click.Option(
        ["--link-expires"], metavar="DURATION", help="links stop working after this long (default: with the tunnel)"
    ),
    click.Option(["--lock-path"], metavar="PATH", help=f"login path on the tunnel's hosts {SERVERS}"),
    click.Option(["--lock-cookie"], metavar="NAME", help=f"login cookie's name {SERVERS}"),
    click.Option(["--lock-header"], metavar="HEADER", help=f"header scripts log in with, as USER:PASSWORD {SERVERS}"),
    click.Option(["--lock-user-header"], metavar="HEADER", help=f"header telling your app who logged in {SERVERS}"),
    click.Option(["--lock-expires"], metavar="DURATION", help=f"how long a login lasts, like 12h {SERVERS}"),
    click.Option(
        ["--lock-confirm-links/--no-lock-confirm-links"],
        default=None,
        help=f"have a link wait for a click, so chat previews don't use it up {SERVERS}",
    ),
    click.Option(["--lock-page"], type=FILE, metavar="FILE", help=f"your own login page {SERVERS}"),
    click.Option(["--lock-link-page"], type=FILE, metavar="FILE", help=f"your own page for opening a link {SERVERS}"),
    click.Option(
        ["--lock-message-page"], type=FILE, metavar="FILE", help=f"your own page for the lock's messages {SERVERS}"
    ),
)
# Every option above, by the name click gives it.
NAMES = frozenset(option.name for option in OPTIONS)


def _settings(options: dict[str, Any]) -> dict[str, Any]:
    """The lock settings given as options, or else in the environment, checked."""
    try:
        found = config.given(LockSettings, os.environ, LOCK_PREFIX)
    except config.ConfigError as exc:
        raise Failure(str(exc), 2) from None
    for name in FIELDS:
        if (value := options.get(f"lock_{name}")) is not None:
            found[name] = value.read_text() if name in PAGES else value
    if errors := problems(merged(DEFAULTS, found), flag):
        raise Failure("; ".join(errors), 2)
    return found


def _guest(users: dict[str, str]) -> str:
    return next(label for n in itertools.count(1) if (label := f"{GUEST}-{n}" if n > 1 else GUEST) not in users)


def _username(raw: str, users: dict[str, str]) -> str:
    username = raw.strip() or _guest(users)
    if not LABEL.fullmatch(username):
        raise Failure(f"--lock: {username!r} can't be a username; use {LABELS}", 2)
    if username in users:
        raise Failure(f"--lock: {username} is given twice", 2)
    return username


def _users(raws: list[str]) -> tuple[dict[str, str], frozenset[str]]:
    users: dict[str, str] = {}
    typed = set()
    for raw in raws:
        given, sep, password = raw.partition(":")
        username = _username(given, users)
        asked = not sep and ask.interactive()
        if asked and (password := ask.secret(f"Password for {username} (empty makes one up)")):
            typed.add(username)
        users[username] = password or secrets.token_urlsafe(PASSWORD_BYTES)
    return users, frozenset(typed)


def _links(raws: list[str], taken: list[str]) -> list[str]:
    labels: list[str] = []
    for raw in raws:
        if raw.strip().isdigit() or raw == BARE:
            labels += next_links([*taken, *labels], int(raw.strip() or 1))
            continue
        for label in filter(None, (part.strip() for part in raw.split(","))):
            if not LABEL.fullmatch(label):
                raise Failure(f"--link: {label!r} can't label a link; use {LABELS}", 2)
            if label in taken or label in labels:
                raise Failure(f"--link: {label} is given twice", 2)
            labels.append(label)
    return labels


def request(options: dict[str, Any]) -> LockRequest | None:
    """The lock `options` ask for; None when they ask for none."""
    locks = list(options.get("lock") or ())
    if not locks and (lines := config.read(LOCK_ENV, os.environ)) is not None:
        locks = [line for line in lines.splitlines() if line.strip()]
    links = list(options.get("link") or ())
    if not links and (raw := os.environ.get(LINK_ENV)) is not None:
        links = [raw]
    settings = _settings(options)
    expires = options.get("link_expires") or os.environ.get(LINK_EXPIRES_ENV)
    if not locks and not links:
        if settings or expires:
            raise Failure("lock settings need --lock or --link", 2)
        return None
    users, typed = _users(locks)
    until = None
    if expires:
        if (length := durations.seconds(expires)) is None:
            raise Failure(f"--link-expires: expected a duration {durations.EXAMPLES}, got {expires!r}", 2)
        until = int(time.time()) + length
    mint = [{"label": label, "expires": until} for label in _links(links, list(users))]
    return LockRequest(users, typed, mint, settings)
