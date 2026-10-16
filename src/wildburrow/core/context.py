import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from wildburrow.auth.base import Authenticator
from wildburrow.core.errors import BindRejected
from wildburrow.core.names import Name, parse_name
from wildburrow.core.registry import Registry
from wildburrow.core.types import Destination, Tunnel

if TYPE_CHECKING:
    from wildburrow.certs.manager import CertManager

log = logging.getLogger(__name__)


class CertificateFailed(BindRejected):
    pass


@dataclass(slots=True)
class ServerContext:
    domain: str
    max_depth: int
    data_dir: Path
    authenticator: Authenticator
    registry: Registry = field(default_factory=Registry)
    certs: CertManager | None = None
    root: Destination | None = None

    async def bind(self, raw: str, tunnel: Tunnel, notify: Callable[[str], None]) -> Name:
        name = parse_name(raw, self.domain, self.max_depth)
        self.registry.bind(name, tunnel)
        if self.certs is None:
            return name
        parent = self.certs.parent(name)
        if not self.certs.ready(parent):
            notify(f"issuing a certificate for *.{parent}")
        try:
            await self.certs.ensure(parent)
        except Exception as exc:
            log.exception("certificate for *.%s failed", parent)
            self.registry.unbind(name, tunnel)
            raise CertificateFailed(f"could not get a certificate for *.{parent}: {exc}") from exc
        return name

    def url(self, name: Name) -> str:
        return f"{'https' if self.certs else 'http'}://{name.fqdn(self.domain)}"
