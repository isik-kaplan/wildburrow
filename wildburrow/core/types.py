from dataclasses import dataclass, field
from typing import Any, Protocol


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


def bound_port(server: Any) -> int:
    """The port a started listener got, which is the one asked for unless that was 0."""
    assert server is not None  # noqa: S101
    return server.sockets[0].getsockname()[1]
