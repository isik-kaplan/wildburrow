import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar

import asyncssh

from wildburrow import tokens
from wildburrow.auth import sshsig
from wildburrow.auth.base import lines
from wildburrow.config import SHOWN, ConfigError
from wildburrow.core.sessions import GRACE_SECONDS
from wildburrow.core.types import Identity, Peer, TokenCredential
from wildburrow.tokens import digest


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
        signers = _signers(settings.signers)
        self._signers = frozenset(signers)
        # Fingerprints, for WILDBURROW_ADMINS=signers.
        self.signers = frozenset(signers.values())
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
        if grant.id in self._deny or (grant.expires is not None and self._clock() > grant.expires + GRACE_SECONDS):
            return None
        # One identity per name, so a person's tokens share their names whichever one they connect with.
        return Identity(grant.name, "token", f"signed:{grant.name}", grant.names, grant.expires, grant.id)


def _hashes(text: str) -> dict[str, str]:
    names = {}
    for line in lines(text):
        name, sep, hexdigest = line.rpartition(":")
        if not sep or not name or len(hexdigest) != 64 or not all(c in "0123456789abcdef" for c in hexdigest):
            raise ConfigError(f"hashes: expected 'name:sha256hex', got {line[:40]!r}")
        names[hexdigest] = name
    return names


def _signers(text: str) -> dict[bytes, str]:
    """Each key's public data and fingerprint."""
    signers = {}
    for line in lines(text):
        try:
            key = asyncssh.import_public_key(line)
        except asyncssh.KeyImportError, ValueError:
            raise ConfigError(f"signers: cannot read the key {line[:40]!r}") from None
        signers[key.public_data] = key.get_fingerprint()
    return signers
