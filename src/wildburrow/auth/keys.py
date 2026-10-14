from dataclasses import dataclass
from typing import ClassVar

import asyncssh

from wildburrow import protocol
from wildburrow.auth import sshsig
from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, Peer, PublicKeyCredential, SignedChallengeCredential


@dataclass(frozen=True, slots=True)
class KeySettings:
    authorized_keys: str


class KeyAuth:
    Settings = KeySettings
    handles: ClassVar[tuple[type, ...]] = (PublicKeyCredential, SignedChallengeCredential)

    def __init__(self, settings: KeySettings) -> None:
        self._keys: dict[bytes, str] = {}
        for line in settings.authorized_keys.splitlines():
            if not (line := line.strip()) or line.startswith("#"):
                continue
            try:
                key = asyncssh.import_public_key(line)
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise ConfigError(f"authorized_keys: cannot parse {line[:40]!r}: {exc}") from None
            self._keys[key.public_data] = key.get_comment() or key.get_fingerprint()
        if not self._keys:
            raise ConfigError("authorized_keys: no keys found")

    async def authenticate(
        self, credential: PublicKeyCredential | SignedChallengeCredential, peer: Peer
    ) -> Identity | None:
        name = self._keys.get(credential.public_key)
        if name is None:
            return None
        if isinstance(credential, SignedChallengeCredential):
            try:
                sshsig.verify(
                    credential.signature, credential.public_key, protocol.SIGNATURE_NAMESPACE, credential.message
                )
            except sshsig.InvalidSignature:
                return None
        return Identity(name, "key")
