from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from wildburrow.core.locks import Lock
    from wildburrow.core.sessions import Session


@dataclass(frozen=True, slots=True)
class Peer:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class Identity:
    name: str
    method: str
    subject: str
    # The names this identity may claim, `*` standing for one label; None for any. Not part of who it is, so the same
    # person keeps their names across tokens that differ in scope.
    names: tuple[str, ...] | None = field(default=None, compare=False)
    # Unix seconds after which the credential stops logging in; None for one that doesn't expire.
    expires: int | None = field(default=None, compare=False)
    # The signed token's id, for denying it.
    token: str = field(default="", compare=False)
    # The user it belongs to, when that isn't its name: a key's comment names a device as `user@device`. One user's
    # identities are their devices, each its own identity but all theirs.
    owner: str = field(default="", compare=False)

    @property
    def user(self) -> str:
        return user_of(self)


def user_of(identity: Identity) -> str:
    return identity.owner or identity.name


@dataclass(frozen=True, slots=True)
class PublicKeyCredential:
    username: str
    public_key: bytes


@dataclass(frozen=True, slots=True)
class PasswordCredential:
    username: str
    password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class TokenCredential:
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class SignedChallengeCredential:
    public_key: bytes
    message: bytes
    signature: str


type Credential = PublicKeyCredential | PasswordCredential | TokenCredential | SignedChallengeCredential


class StreamReader(Protocol):
    async def read(self, n: int = -1) -> bytes: ...


class StreamWriter(Protocol):
    def write(self, data: bytes) -> None: ...
    def can_write_eof(self) -> bool: ...
    def write_eof(self) -> None: ...
    def close(self) -> None: ...
    async def drain(self) -> None: ...


class Destination(Protocol):
    async def open_stream(self, peer: Peer) -> tuple[StreamReader, StreamWriter]: ...


class Tunnel(Destination, Protocol):
    identity: Identity
    # The login it came from; None for one no session tracks.
    session: Session | None
    # What visitors need before they reach it; None for an open tunnel.
    lock: Lock | None
    # Whether its client asked for search engines to index it; None for the server's default.
    index: bool | None
    # Its binds in the server's record, closed when it lets go of its names.
    records: list[int]


def bound_port(server: Any) -> int:
    """The port a started listener got, which is the one asked for unless that was 0."""
    assert server is not None  # noqa: S101
    return server.sockets[0].getsockname()[1]
