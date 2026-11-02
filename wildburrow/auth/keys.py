from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

import asyncssh

from wildburrow import protocol
from wildburrow.auth import sshsig
from wildburrow.auth.base import USER_NAME, lines, nobody
from wildburrow.config import SHOWN, ConfigError
from wildburrow.core.types import Identity, Peer, PublicKeyCredential, SignedChallengeCredential

if TYPE_CHECKING:
    from wildburrow.core.users import Users

# The keys that can already log in to the account the server runs as.
DEFAULT_AUTHORIZED_KEYS = Path("~/.ssh/authorized_keys")


@dataclass(frozen=True, slots=True)
class KeySettings:
    authorized_keys: str = field(default="", metadata={SHOWN: str(DEFAULT_AUTHORIZED_KEYS)})
    # One `name:SHA256:fingerprint` line per key, naming the user it logs in; a key no line names is its own user.
    users: str = ""


def _default_keys() -> str:
    try:
        return DEFAULT_AUTHORIZED_KEYS.expanduser().read_text()
    except (OSError, RuntimeError) as exc:
        raise ConfigError(f"authorized_keys: not set, and {DEFAULT_AUTHORIZED_KEYS} is unreadable: {exc}") from None


class KeyAuth:
    Settings = KeySettings
    handles: ClassVar[tuple[type, ...]] = (PublicKeyCredential, SignedChallengeCredential)

    def __init__(self, settings: KeySettings) -> None:
        found: dict[bytes, tuple[str, str]] = {}
        for line in lines(settings.authorized_keys or _default_keys()):
            try:
                key = asyncssh.import_public_key(line)
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise ConfigError(f"authorized_keys: cannot parse {line[:40]!r}: {exc}") from None
            found[key.public_data] = (key.get_comment() or "", key.get_fingerprint())
        if not found:
            raise ConfigError("authorized_keys: no keys found")
        owners = _owners(settings.users, {fingerprint for _, fingerprint in found.values()})
        # Each key's user, the label it's shown by (its comment, else its user), and its fingerprint.
        self._keys: dict[bytes, tuple[str, str, str]] = {}
        for data, (comment, fingerprint) in found.items():
            user = owners.get(fingerprint, fingerprint)
            self._keys[data] = (user, comment or user, fingerprint)
        # Keys database users joined with: the user, the key's fingerprint and its device. Set once users are open.
        self.database: Callable[[bytes], tuple[str, str, str] | None] = nobody

    def users(self) -> set[str]:
        """The users these keys log in."""
        return {user for user, _, _ in self._keys.values()}

    def fingerprints(self) -> set[str]:
        return {fingerprint for _, _, fingerprint in self._keys.values()}

    def comments(self) -> set[str]:
        """What the keys are shown as that isn't their user: no admin rule can name them by it."""
        return {label for user, label, _ in self._keys.values() if label != user}

    def logins(self) -> list[Identity]:
        """The identity each key logs in as."""
        return [Identity(label, "key", fingerprint, owner=user) for user, label, fingerprint in self._keys.values()]

    def look_up(self, users: Users) -> None:
        self.database = users.key

    async def authenticate(
        self, credential: PublicKeyCredential | SignedChallengeCredential, peer: Peer
    ) -> Identity | None:
        if (found := self._keys.get(credential.public_key)) is not None:
            user, name, fingerprint = found
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


def _owners(text: str, fingerprints: set[str]) -> dict[str, str]:
    """Each named key's user, by its fingerprint."""
    owners: dict[str, str] = {}
    for line in lines(text):
        name, sep, fingerprint = line.partition(":")
        if not sep or not USER_NAME.fullmatch(name) or not fingerprint.startswith("SHA256:"):
            raise ConfigError(f"users: expected 'name:SHA256:fingerprint', got {line[:60]!r}")
        if fingerprint in owners:
            raise ConfigError(f"users: {fingerprint} is given twice")
        if fingerprint not in fingerprints:
            raise ConfigError(f"users: {fingerprint} ({name}'s) isn't one of the authorized keys")
        owners[fingerprint] = name
    return owners
