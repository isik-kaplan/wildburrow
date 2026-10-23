import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wildburrow.auth.base import Authenticator
from wildburrow.core.errors import BindRejected
from wildburrow.core.names import Name, allows, parse_name
from wildburrow.core.registry import NameTaken, Registry
from wildburrow.core.sessions import Policy, Session, Sessions, describe
from wildburrow.core.types import Destination, Tunnel

if TYPE_CHECKING:
    from wildburrow.certs.manager import CertManager

log = logging.getLogger(__name__)


class CertificateFailed(BindRejected):
    pass


class NotAllowed(BindRejected):
    pass


@dataclass(slots=True)
class ServerContext:
    domain: str
    max_depth: int
    data_dir: Path
    authenticator: Authenticator
    registry: Registry = field(default_factory=Registry)
    sessions: Sessions = field(default_factory=Sessions)
    policy: Policy = field(default_factory=Policy)
    certs: CertManager | None = None
    root: Destination | None = None
    # What clients are told about logging in, published once the transports know their ports.
    info: bytes = b"{}"

    async def bind(self, raw: str, tunnel: Tunnel, notify: Callable[[str], None]) -> Name:
        [name] = await self.bind_all([raw], tunnel, notify)
        return name

    async def bind_all(self, raws: Sequence[str], tunnel: Tunnel, notify: Callable[[str], None]) -> list[Name]:
        """Every one of `raws` bound to `tunnel`, or none of them, refused with everything that stood in the way."""
        names: list[Name] = []
        problems: list[BindRejected] = []
        for raw in dict.fromkeys(raws):
            try:
                names.append(self._check(raw, tunnel))
            except BindRejected as exc:
                problems.append(exc)
        if len(problems) == 1:
            raise problems[0]
        if problems:
            raise BindRejected("; ".join(map(str, problems)))
        # Checked and bound with nothing awaited in between, so no other connection can slip in.
        for name in names:
            self.registry.bind(name, tunnel)
        try:
            await self._certify(names, notify)
        except CertificateFailed:
            for name in names:
                self.registry.unbind(name, tunnel)
            raise
        return names

    def _check(self, raw: str, tunnel: Tunnel) -> Name:
        name = parse_name(raw, self.domain, self.max_depth)
        if not allows(patterns := tunnel.identity.names, name):
            raise NotAllowed(f"{name}: {tunnel.identity.name} may only claim {', '.join(patterns or ())}")
        if (holder := self.registry.holder(name)) is not None and holder.identity != tunnel.identity:
            raise NameTaken(name, holder)
        return name

    async def _certify(self, names: list[Name], notify: Callable[[str], None]) -> None:
        if self.certs is None:
            return
        for parent in dict.fromkeys(self.certs.parent(name) for name in names):
            if not self.certs.ready(parent):
                notify(f"issuing a certificate for *.{parent}")
            try:
                await self.certs.ensure(parent)
            except Exception as exc:
                log.exception("certificate for *.%s failed", parent)
                raise CertificateFailed(f"could not get a certificate for *.{parent}: {exc}") from exc

    def names_of(self, session: Session) -> list[str]:
        return [str(name) for name, tunnel in self.registry.holders().items() if tunnel.session is session]

    def listing(self, actor: Session) -> list[dict[str, Any]]:
        """The other sessions `actor` may see, as it is told about them."""
        admin = actor.identity in self.policy.admins
        return [
            describe(session, self.names_of(session), actor.identity, admin)
            for session in self.sessions
            if session is not actor and self.policy.sees(actor.identity, session.identity)
        ]

    def kick(self, actor: Session, request: dict[str, Any]) -> dict[str, Any]:
        """Ends the sessions `request` picks by id, held name or identity, among those `actor` may see."""
        targets = [
            session
            for session in self._picked(request)
            if session is not actor and self.policy.sees(actor.identity, session.identity)
        ]
        admin = actor.identity in self.policy.admins
        kicked, refused = [], []
        for session in targets:
            if self.policy.kicks(actor.identity, session.identity):
                kicked.append(describe(session, self.names_of(session), actor.identity, admin))
                log.info("%s ended session %s of %s", actor.identity.name, session.id, session.identity.name)
                session.end(f"ended by {actor.identity.name}")
            else:
                refused.append(session.id)
        return {"sessions": kicked, "refused": refused}

    def _picked(self, request: dict[str, Any]) -> list[Session]:
        if "session" in request:
            return [session for session in self.sessions if session.id == str(request["session"])]
        if "who" in request:
            return [session for session in self.sessions if session.identity.name == str(request["who"])]
        raw = str(request["name"]).lower()
        held = self.registry.holders().items()
        return [tunnel.session for name, tunnel in held if str(name) == raw and tunnel.session is not None]

    def url(self, name: Name) -> str:
        return f"{'https' if self.certs else 'http'}://{name.fqdn(self.domain)}"
