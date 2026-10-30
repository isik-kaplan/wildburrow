"""Who is logged in right now, kept in memory only, and who may see or end whose session."""

import asyncio
import secrets
import time
from collections.abc import Callable, Collection, Iterator
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from wildburrow.config import PREFIX, ConfigError
from wildburrow.core.types import Identity, Peer

# How far a minting machine's clock may run ahead of the server's; a token is honoured this long past its expiry.
GRACE_SECONDS = 60
ID_BYTES = 6
EXPIRED = "the token expired"
NONE = "none"
ALL = "all"
SIGNERS = "signers"


class Level(IntEnum):
    NONE = 0
    OWN = 1
    # Admins reach everyone who isn't an admin.
    ADMINS = 2
    ALL = 3


LEVELS = {level.name.lower(): level for level in Level}


def level(var: str, raw: str) -> Level:
    try:
        return LEVELS[raw.strip().lower()]
    except KeyError:
        raise ConfigError(f"{var}: expected one of {', '.join(LEVELS)}, got {raw!r}") from None


@dataclass(frozen=True, slots=True)
class Admins:
    """Who counts as an admin: any identity matching one of the rules."""

    everyone: bool = False
    methods: frozenset[str] = frozenset()
    # (method, name or subject) pairs.
    exact: frozenset[tuple[str, str]] = frozenset()
    # Fingerprints of key logins that count, from the token signers.
    keys: frozenset[str] = frozenset()

    @classmethod
    def parse(cls, var: str, rules: Collection[str], auth: Collection[str], signers: Collection[str]) -> Admins:
        rules = [rule.strip() for rule in rules]
        if NONE in rules:
            if len(rules) > 1:
                raise ConfigError(f"{var}: {NONE} can't be combined with other rules")
            return cls()
        if ALL in rules:
            return cls(everyone=True)
        methods, exact = set(), set()
        for rule in rules:
            method, sep, value = rule.partition(":")
            if rule == SIGNERS:
                continue
            if method not in auth:
                known = ", ".join([NONE, ALL, SIGNERS, *auth])
                raise ConfigError(f"{var}: {rule!r} is neither a rule nor one of the auth methods; expected {known}")
            if not sep:
                methods.add(method)
            elif not value:
                raise ConfigError(f"{var}: {rule!r} names no one; give a name after the colon")
            else:
                exact.add((method, value))
        keys = frozenset(signers) if SIGNERS in rules else frozenset()
        return cls(methods=frozenset(methods), exact=frozenset(exact), keys=keys)

    def __contains__(self, identity: Identity) -> bool:
        return (
            self.everyone
            or identity.method in self.methods
            or (identity.method, identity.name) in self.exact
            or (identity.method, identity.subject) in self.exact
            or (identity.method == "key" and identity.subject in self.keys)
        )


@dataclass(frozen=True, slots=True)
class Policy:
    admins: Admins = Admins()
    see: Level = Level.ADMINS
    kick: Level = Level.ADMINS

    def __post_init__(self) -> None:
        if self.kick > self.see:
            raise ConfigError(f"{PREFIX}KICK reaches further than {PREFIX}SEE, and no one can end what they can't see")

    def sees(self, actor: Identity, target: Identity) -> bool:
        return self._reaches(self.see, actor, target)

    def kicks(self, actor: Identity, target: Identity) -> bool:
        return self._reaches(self.kick, actor, target)

    def _reaches(self, level: Level, actor: Identity, target: Identity) -> bool:
        if level is Level.NONE:
            return False
        if actor == target:
            return True
        return level >= Level.ADMINS and actor in self.admins and (level is Level.ALL or target not in self.admins)


@dataclass(eq=False, slots=True)
class Session:
    id: str
    identity: Identity
    transport: str
    peer: Peer
    since: int
    # Closes the connection, telling the client why.
    end: Callable[[str], None]
    timer: asyncio.TimerHandle | None = field(default=None, repr=False)
    # Why the server ended it, when it did, and the recorded command that did, if one did.
    reason: str | None = None
    ended_by: int | None = None


class Sessions:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._sessions: dict[str, Session] = {}
        self._clock = clock

    def open(self, identity: Identity, transport: str, peer: Peer, end: Callable[[str], None]) -> Session:
        session = Session(secrets.token_hex(ID_BYTES), identity, transport, peer, int(self._clock()), end)
        if identity.expires is not None:
            left = identity.expires + GRACE_SECONDS - self._clock()
            session.timer = asyncio.get_running_loop().call_later(max(left, 0), end, EXPIRED)
        self._sessions[session.id] = session
        return session

    def close(self, session: Session) -> None:
        self._sessions.pop(session.id, None)
        if session.timer is not None:
            session.timer.cancel()

    def __iter__(self) -> Iterator[Session]:
        return iter(list(self._sessions.values()))


def describe(session: Session, names: list[str], shown_to: Identity, admin: bool) -> dict[str, Any]:
    """What `shown_to` is told about `session`: its address only for admins and for their own."""
    identity = session.identity
    yours = shown_to == identity
    entry = {
        "id": session.id,
        "who": identity.name,
        "via": identity.method,
        "transport": session.transport,
        "names": names,
        "since": session.since,
        "expires": identity.expires,
        "token": identity.token,
        "yours": yours,
    }
    if admin or yours:
        entry["from"] = session.peer.host
    return entry
