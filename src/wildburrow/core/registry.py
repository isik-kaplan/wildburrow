from wildburrow.core.errors import BindRejected
from wildburrow.core.names import Name
from wildburrow.core.types import Tunnel


class NameTaken(BindRejected):
    def __init__(self, name: Name, holder: Tunnel) -> None:
        super().__init__(f"{name} is already bound by {holder.identity.name}")


class Registry:
    def __init__(self) -> None:
        self._tunnels: dict[Name, Tunnel] = {}

    # The same identity may move a name to a new connection, so a reconnecting client doesn't wait for the
    # server to notice that its old connection is gone.
    def bind(self, name: Name, tunnel: Tunnel) -> None:
        if (holder := self._tunnels.get(name)) is not None and holder.identity != tunnel.identity:
            raise NameTaken(name, holder)
        self._tunnels[name] = tunnel

    def unbind(self, name: Name, tunnel: Tunnel) -> None:
        if self._tunnels.get(name) is tunnel:
            del self._tunnels[name]

    def names(self) -> list[Name]:
        return list(self._tunnels)

    def resolve(self, labels: tuple[str, ...]) -> Tunnel | None:
        if (tunnel := self._tunnels.get(Name(labels))) is not None:
            return tunnel
        return self._tunnels.get(Name(labels[1:], wildcard=True)) if len(labels) > 1 else None
