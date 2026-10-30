from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

import asyncssh

from wildburrow import protocol
from wildburrow.auth import sshsig
from wildburrow.auth.base import nobody
from wildburrow.config import SHOWN, ConfigError
from wildburrow.core.types import Identity, Peer, PublicKeyCredential, SignedChallengeCredential

if TYPE_CHECKING:
    from wildburrow.core.users import Users

# The keys that can already log in to the account the server runs as.
DEFAULT_AUTHORIZED_KEYS = Path("~/.ssh/authorized_keys")


@dataclass(frozen=True, slots=True)
class KeySettings:
    authorized_keys: str = field(default="", metadata={SHOWN: str(DEFAULT_AUTHORIZED_KEYS)})


def _default_keys() -> str:
    try:
        return DEFAULT_AUTHORIZED_KEYS.expanduser().read_text()
    except (OSError, RuntimeError) as exc:
        raise ConfigError(f"authorized_keys: not set, and {DEFAULT_AUTHORIZED_KEYS} is unreadable: {exc}") from None


class KeyAuth:
    Settings = KeySettings
    handles: ClassVar[tuple[type, ...]] = (PublicKeyCredential, SignedChallengeCredential)

    def __init__(self, settings: KeySettings) -> None:
        self._keys: dict[bytes, tuple[str, str]] = {}
        for line in (settings.authorized_keys or _default_keys()).splitlines():
            if not (line := line.strip()) or line.startswith("#"):
                continue
            try:
                key = asyncssh.import_public_key(line)
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise ConfigError(f"authorized_keys: cannot parse {line[:40]!r}: {exc}") from None
            fingerprint = key.get_fingerprint()
            self._keys[key.public_data] = (key.get_comment() or fingerprint, fingerprint)
        if not self._keys:
            raise ConfigError("authorized_keys: no keys found")
        # Keys database users joined with: the user, the key's fingerprint and its device. Set once users are open.
        self.database: Callable[[bytes], tuple[str, str, str] | None] = nobody

    def users(self) -> set[str]:
        """The users these keys log in."""
        return {owner(name) for name, _ in self._keys.values()}

    def fingerprints(self) -> set[str]:
        return {fingerprint for _, fingerprint in self._keys.values()}

    def look_up(self, users: Users) -> None:
        self.database = users.key

    async def authenticate(
        self, credential: PublicKeyCredential | SignedChallengeCredential, peer: Peer
    ) -> Identity | None:
        if (found := self._keys.get(credential.public_key)) is not None:
            name, fingerprint = found
            user = owner(name)
        elif (joined := self.database(credential.public_key)) is not None:
            user, fingerprint, device = joined
            name = f"{user}@{device}"
        else:
            return None
        if isinstance(credential, SignedChallengeCredential):
            try:
                sshsig.verify(
                    credential.signature, credential.public_key, protocol.SIGNATURE_NAMESPACE, credential.message
                )
            except sshsig.InvalidSignature:
                return None
        return Identity(name, "key", fingerprint, owner=user)


def owner(comment: str) -> str:
    """The user a key's comment names: `isik@laptop` is isik's, on their laptop."""
    return comment.partition("@")[0] or comment
