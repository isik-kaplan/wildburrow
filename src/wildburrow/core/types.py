from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Peer:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class Identity:
    name: str
    method: str
    subject: str


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
    username: str
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


class Tunnel(Protocol):
    identity: Identity

    async def open_stream(self, peer: Peer) -> tuple[StreamReader, StreamWriter]: ...
