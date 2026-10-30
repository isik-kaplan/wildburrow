import asyncio
import secrets
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError

from wildburrow.auth.base import USER_NAME, lines
from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, PasswordCredential, Peer


@dataclass(frozen=True, slots=True)
class PasswordSettings:
    # One `name:argon2hash` line per user, from `wildburrow passwords hash NAME`.
    users: str
    max_failures: int = 5
    block_seconds: int = 900


class PasswordAuth:
    Settings = PasswordSettings
    handles: ClassVar[tuple[type, ...]] = (PasswordCredential,)

    def __init__(self, settings: PasswordSettings, clock: Callable[[], float] = time.monotonic) -> None:
        self._users = _users(settings.users)
        if settings.max_failures < 1 or settings.block_seconds < 1:
            raise ConfigError("max_failures and block_seconds must be at least 1")
        self._settings = settings
        self._clock = clock
        self._hasher = PasswordHasher()
        # What an unknown name's password is checked against, so how long a login takes doesn't say which names exist.
        # No one knows its password, so it never lets anyone in.
        self._decoy = self._hasher.hash(secrets.token_hex())
        self._failures: dict[str, deque[float]] = {}

    def blocked(self, host: str) -> bool:
        self._expire()
        return len(self._failures.get(host, ())) >= self._settings.max_failures

    async def authenticate(self, credential: PasswordCredential, peer: Peer) -> Identity | None:
        if self.blocked(peer.host):
            return None
        attempt = self._clock()
        failures = self._failures.setdefault(peer.host, deque())
        failures.append(attempt)
        hashed = self._users.get(credential.username, self._decoy)
        if await asyncio.to_thread(self._verify, hashed, credential.password):
            failures.remove(attempt)
            return Identity(credential.username, "password", credential.username)
        return None

    def _verify(self, hashed: str, password: str) -> bool:
        try:
            return self._hasher.verify(hashed, password)
        except VerificationError:
            return False

    def _expire(self) -> None:
        cutoff = self._clock() - self._settings.block_seconds
        for host in list(self._failures):
            failures = self._failures[host]
            while failures and failures[0] <= cutoff:
                failures.popleft()
            if not failures:
                del self._failures[host]


def _users(text: str) -> dict[str, str]:
    users: dict[str, str] = {}
    for line in lines(text):
        # A line's hash is a secret, so errors name only the user.
        name, sep, hashed = line.partition(":")
        if not sep or not USER_NAME.fullmatch(name):
            raise ConfigError(f"users: expected 'name:argon2hash', got a line starting {name[:20]!r}")
        if name in users:
            raise ConfigError(f"users: {name} is given twice")
        try:
            extract_parameters(hashed)
        except InvalidHashError:
            raise ConfigError(
                f"users: {name}'s hash isn't an argon2 hash; make one with `wildburrow passwords hash {name}`"
            ) from None
        users[name] = hashed
    if not users:
        raise ConfigError("users: none given; add a line for each with `wildburrow passwords hash NAME`")
    return users
