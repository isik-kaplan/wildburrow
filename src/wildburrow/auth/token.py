import hashlib
import secrets
from dataclasses import dataclass
from typing import ClassVar

from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, Peer, TokenCredential

PREFIX = "wb_"


def new_token() -> str:
    return PREFIX + secrets.token_urlsafe(32)


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class TokenSettings:
    hashes: str


class TokenAuth:
    Settings = TokenSettings
    handles: ClassVar[tuple[type, ...]] = (TokenCredential,)

    def __init__(self, settings: TokenSettings) -> None:
        self._names: dict[str, str] = {}
        for line in settings.hashes.splitlines():
            if not (line := line.strip()) or line.startswith("#"):
                continue
            name, sep, hexdigest = line.rpartition(":")
            if not sep or not name or len(hexdigest) != 64 or not all(c in "0123456789abcdef" for c in hexdigest):
                raise ConfigError(f"hashes: expected 'name:sha256hex', got {line[:40]!r}")
            self._names[hexdigest] = name
        if not self._names:
            raise ConfigError("hashes: no tokens found")

    async def authenticate(self, credential: TokenCredential, peer: Peer) -> Identity | None:
        name = self._names.get(digest(credential.token))
        return Identity(name, "token") if name is not None else None
