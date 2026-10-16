import hashlib
import secrets
from dataclasses import dataclass
from typing import ClassVar

from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, Peer, TokenCredential

PREFIX = "wb_"
TOKEN_BYTES = 32


def new_token() -> str:
    # The only mutant left here, token_urlsafe(None), asks for the default of 32 bytes.
    return PREFIX + secrets.token_urlsafe(TOKEN_BYTES)  # pragma: no mutate


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
        hexdigest = digest(credential.token)
        name = self._names.get(hexdigest)
        return Identity(name, "token", hexdigest) if name is not None else None
