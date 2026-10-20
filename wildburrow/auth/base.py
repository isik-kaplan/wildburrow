from collections.abc import Mapping, Sequence
from typing import ClassVar, Protocol

from wildburrow.core.types import Credential, Identity, Peer


class AuthProvider(Protocol):
    handles: ClassVar[tuple[type, ...]]

    async def authenticate(self, credential: Credential, peer: Peer) -> Identity | None: ...


class Authenticator:
    def __init__(self, providers: Sequence[AuthProvider]) -> None:
        self._providers = tuple(providers)

    def accepts(self, kind: type) -> bool:
        return any(kind in provider.handles for provider in self._providers)

    def methods(self, kinds: Mapping[str, type]) -> list[str]:
        """The named methods some provider takes, in the order the providers are tried."""
        found = [method for provider in self._providers for method, kind in kinds.items() if kind in provider.handles]
        return list(dict.fromkeys(found))

    async def authenticate(self, credential: Credential, peer: Peer) -> Identity | None:
        for provider in self._providers:
            if type(credential) in provider.handles and (identity := await provider.authenticate(credential, peer)):
                return identity
        return None
