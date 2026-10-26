"""`--lock` and `--link`, from the command line or the environment, turned into the lock the client asks for."""

import itertools
import secrets
import time

from isik.common.settings import UNSET

from wildburrow import durations
from wildburrow.cli import ask
from wildburrow.cli.errors import Failure
from wildburrow.cli.settings import BARE, Tunnel
from wildburrow.client.locking import LockRequest
from wildburrow.locks import GUEST, LABEL, PASSWORD_BYTES, next_links

LABELS = "1-64 letters, digits and . _ @ -"


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


def _links(raws: list[str]) -> list[str]:
    """Each link's label, which a password may share: both then log in as the one name."""
    labels: list[str] = []
    for raw in raws:
        if raw.strip().isdigit() or raw == BARE:
            labels += next_links(labels, int(raw.strip() or 1))
            continue
        for label in filter(None, (part.strip() for part in raw.split(","))):
            if not LABEL.fullmatch(label):
                raise Failure(f"--links: {label!r} can't label a link; use {LABELS}", 2)
            if label in labels:
                raise Failure(f"--links: {label} is given twice", 2)
            labels.append(label)
    return labels


def request(settings: Tunnel) -> LockRequest | None:
    """The lock `settings` ask for; None when they ask for none."""
    links = [*settings.links, *[BARE] * settings.link]
    locks = [*settings.lock, *[BARE] * settings.lock_guest]
    if settings.locked and not locks and not links:
        # Asking for a lock and naming no one makes up a username and password.
        locks = [BARE]
    if not locks and not links:
        return None
    users, typed = _users(locks)
    until = None
    if settings.link_expires is not UNSET:
        until = int(time.time()) + durations.seconds(settings.link_expires)
    mint = [{"label": label, "expires": until, "uses": settings.link_uses} for label in _links(links)]
    return LockRequest(users, typed, mint, settings.lock_settings())
