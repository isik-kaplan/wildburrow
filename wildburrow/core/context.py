import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wildburrow.auth.base import Authenticator
from wildburrow.core.errors import BindRejected
from wildburrow.core.locks import Lock, Locking, build
from wildburrow.core.names import InvalidName, Name, allows, host_labels, parse_name
from wildburrow.core.registry import NameTaken, Registry
from wildburrow.core.sessions import Policy, Session, Sessions, describe, same
from wildburrow.core.types import Destination, Identity, Tunnel
from wildburrow.locks import LABEL, next_links, safe_path

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
    locking: Locking = field(default_factory=Locking)
    # Every lock by its id, for the server's own domain to find the ones homed there.
    locks: dict[str, Lock] = field(default_factory=dict)
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

    def lock(
        self, tunnel: Tunnel, raws: Sequence[str], spec: Any, changed: Callable[[dict[str, Any]], None]
    ) -> list[dict[str, str]]:
        """Locks `tunnel` as `spec` asks, before any of `raws` is bound to it; returns the links minted for it."""
        if tunnel.lock is not None:
            raise BindRejected("this tunnel is already locked")
        plain = []
        for raw in raws:
            try:
                name = parse_name(raw, self.domain, self.max_depth)
            except InvalidName:
                continue
            if not name.wildcard:
                plain.append(name.fqdn(self.domain))
        home = plain[0] if plain else self.domain
        try:
            lock, minted = build(spec, home, not plain, self.certs is not None, self.locking, changed)
        except ValueError as exc:
            raise BindRejected(f"lock: {exc}") from None
        tunnel.lock = self.locks[lock.id] = lock
        return [{"label": label, "url": lock.link_url(key)} for label, key in minted]

    def unlock(self, tunnel: Tunnel) -> None:
        if (lock := tunnel.lock) is not None and self.locks.get(lock.id) is lock:
            del self.locks[lock.id]

    def _locked(self, actor: Identity) -> list[tuple[Tunnel, Lock]]:
        """The locked tunnels of `actor`'s own identity, each once, with their locks."""
        found = {id(tunnel): tunnel for tunnel in self.registry.holders().values()}
        return [
            (tunnel, tunnel.lock)
            for tunnel in found.values()
            if tunnel.lock is not None and same(actor, tunnel.identity)
        ]

    def _held(self, tunnel: Tunnel) -> list[str]:
        return [str(name) for name, holder in self.registry.holders().items() if holder is tunnel]

    def logins(self, actor: Identity) -> list[dict[str, Any]]:
        """Who may get into each of `actor`'s locked tunnels, and who has."""
        return [{"names": self._held(tunnel), "logins": lock.listing()} for tunnel, lock in self._locked(actor)]

    def mint(self, actor: Identity, request: dict[str, Any]) -> dict[str, Any]:
        """One more link to a locked tunnel of `actor`'s, landing on the URL `request` names."""
        address = str(request["url"]).strip()
        host, _, path = address.split("://", 1)[-1].partition("/")
        host, path = host.partition(":")[0].lower(), f"/{path}"
        labels = host_labels(host, self.domain)
        tunnel = None if labels is None else self.registry.resolve(labels)
        if tunnel is None or tunnel.lock is None or not same(actor, tunnel.identity):
            return {"error": f"no locked tunnel of yours serves {host or address!r}"}
        if not safe_path(path):
            return {"error": f"a link can't land on {path!r}"}
        lock = tunnel.lock
        [label] = [str(request["label"])] if request.get("label") else next_links(lock.entries, 1)
        if not LABEL.fullmatch(label) or label in lock.entries:
            return {"error": f"{label!r} is taken or can't name a login"}
        expires = request.get("expires")
        key = lock.mint(label, host, path, expires if isinstance(expires, int) else None)
        return {"label": label, "url": lock.link_url(key)}

    def end_login(self, actor: Identity, who: str) -> dict[str, Any]:
        """Ends `who`'s password or link in every locked tunnel of `actor`'s, logging out whoever used it."""
        ended = [self._held(tunnel) for tunnel, lock in self._locked(actor) if lock.end(who)]
        return {"who": who, "ended": ended}
