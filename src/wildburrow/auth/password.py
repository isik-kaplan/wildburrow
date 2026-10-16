import asyncio
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError

from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, PasswordCredential, Peer


@dataclass(frozen=True, slots=True)
class PasswordSettings:
    hash: str
    max_failures: int = 5
    block_seconds: int = 900


class PasswordAuth:
    Settings = PasswordSettings
    handles: ClassVar[tuple[type, ...]] = (PasswordCredential,)

    def __init__(self, settings: PasswordSettings, clock: Callable[[], float] = time.monotonic) -> None:
        try:
            extract_parameters(settings.hash)
        except InvalidHashError:
            raise ConfigError("hash: not an argon2 hash; create one with `wildburrow hash-password`") from None
        if settings.max_failures < 1 or settings.block_seconds < 1:
            raise ConfigError("max_failures and block_seconds must be at least 1")
        self._settings = settings
        self._clock = clock
        self._hasher = PasswordHasher()
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
        if await asyncio.to_thread(self._verify, credential.password):
            failures.remove(attempt)
            return Identity(credential.username, "password", credential.username)
        return None

    def _verify(self, password: str) -> bool:
        try:
            return self._hasher.verify(self._settings.hash, password)
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
