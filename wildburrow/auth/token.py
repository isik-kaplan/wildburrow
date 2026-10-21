import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar

import asyncssh

from wildburrow import tokens
from wildburrow.auth import sshsig
from wildburrow.config import SHOWN, ConfigError
from wildburrow.core.types import Identity, Peer, TokenCredential
from wildburrow.tokens import digest

# How far the minting machine's clock may be ahead of the server's before a fresh token reads as expired.
SKEW_SECONDS = 60


@dataclass(frozen=True, slots=True)
class TokenSettings:
    hashes: str = ""
    signers: str = ""
    deny: tuple[str, ...] = field(default=(), metadata={SHOWN: "none"})


class TokenAuth:
    Settings = TokenSettings
    handles: ClassVar[tuple[type, ...]] = (TokenCredential,)

    def __init__(self, settings: TokenSettings, clock: Callable[[], float] = time.time) -> None:
        self._names = _hashes(settings.hashes)
        self._signers = _signers(settings.signers)
        if not self._names and not self._signers:
            raise ConfigError("set hashes, signers, or both")
        self._deny = frozenset(settings.deny)
        self._clock = clock

    async def authenticate(self, credential: TokenCredential, peer: Peer) -> Identity | None:
        if credential.token.startswith(tokens.PREFIX):
            return self._signed(credential.token)
        hexdigest = digest(credential.token)
        name = self._names.get(hexdigest)
        return Identity(name, "token", hexdigest) if name is not None else None

    def _signed(self, token: str) -> Identity | None:
        try:
            grant, payload, signature = tokens.decode(token)
            signer = sshsig.signer(signature)
            if signer not in self._signers:
                return None
            sshsig.verify(tokens.armor(signature), signer, tokens.NAMESPACE, payload)
        except ValueError, sshsig.InvalidSignature:
            return None
        if grant.id in self._deny or (grant.expires is not None and self._clock() > grant.expires + SKEW_SECONDS):
            return None
        # One identity per name, so a person's tokens share their names whichever one they connect with.
        return Identity(grant.name, "token", f"signed:{grant.name}", grant.names)


def _lines(text: str) -> list[str]:
    return [line for line in (raw.strip() for raw in text.splitlines()) if line and not line.startswith("#")]


def _hashes(text: str) -> dict[str, str]:
    names = {}
    for line in _lines(text):
        name, sep, hexdigest = line.rpartition(":")
        if not sep or not name or len(hexdigest) != 64 or not all(c in "0123456789abcdef" for c in hexdigest):
            raise ConfigError(f"hashes: expected 'name:sha256hex', got {line[:40]!r}")
        names[hexdigest] = name
    return names


def _signers(text: str) -> frozenset[bytes]:
    signers = set()
    for line in _lines(text):
        try:
            signers.add(asyncssh.import_public_key(line).public_data)
        except asyncssh.KeyImportError, ValueError:
            raise ConfigError(f"signers: cannot read the key {line[:40]!r}") from None
    return frozenset(signers)
