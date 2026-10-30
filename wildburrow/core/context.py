import asyncio
import dataclasses
import hashlib
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import asyncssh
from argon2 import PasswordHasher

from wildburrow.auth.base import Authenticator
from wildburrow.core.errors import BindRejected
from wildburrow.core.indexing import Indexing, indexed
from wildburrow.core.locks import Lock, Locking, build, entry_id
from wildburrow.core.names import InvalidName, Name, allows, host_labels, parse_name
from wildburrow.core.registry import NameTaken, Registry
from wildburrow.core.sessions import Policy, Session, Sessions, describe, same
from wildburrow.core.types import (
    Credential,
    Destination,
    Identity,
    PasswordCredential,
    Peer,
    PublicKeyCredential,
    SignedChallengeCredential,
    TokenCredential,
    Tunnel,
)
from wildburrow.core.users import INVITE_SECONDS, Key, UserError, Users
from wildburrow.locks import LABEL, LINK, PAGES, next_links, safe_path
from wildburrow.store.record import Recorder, acting
from wildburrow.store.users import UserStore

if TYPE_CHECKING:
    from wildburrow.certs.manager import CertManager

log = logging.getLogger(__name__)


class CertificateFailed(BindRejected):
    pass


class NotAllowed(BindRejected):
    pass


REFUSED = "refused"
DENIED = "denied"
# Let in by a credential, but not as a user who may log in here: a token signed for a database user's name, say.
NOT_A_USER = "not-a-user"
# How each kind of credential logs in, as recorded.
METHODS = {
    PublicKeyCredential: "key", SignedChallengeCredential: "key", PasswordCredential: "password",
    TokenCredential: "token",
}  # fmt: skip


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
    indexing: Indexing = Indexing.OPT_IN
    record: Recorder = field(default_factory=Recorder)
    users: Users = field(default_factory=lambda: Users(UserStore(None)))
    # Ids of signed tokens denied while the server runs, or in an earlier run on file.
    denied: set[str] = field(default_factory=set)
    # What clients are told about logging in, published once the transports know their ports.
    info: bytes = b"{}"

    async def bind(self, raw: str, tunnel: Tunnel, notify: Callable[[str], None]) -> Name:
        [name] = await self.bind_all([raw], tunnel, notify)
        return name

    async def bind_all(self, raws: Sequence[str], tunnel: Tunnel, notify: Callable[[str], None]) -> list[Name]:
        """Every one of `raws` bound to `tunnel`, or none of them, refused with everything that stood in the way."""
        try:
            names = await self._bind_all(raws, tunnel, notify)
        except BindRejected as exc:
            if tunnel.session is not None:
                self.record.tunnel_rejected(tunnel.session, list(raws), str(exc))
            raise
        if tunnel.session is not None:
            urls = {str(name): self.url(name) for name in names}
            tunnel.records.append(self.record.tunnel_opened(tunnel.session, tunnel.lock, self.indexed(tunnel), urls))
        return names

    def release(self, tunnel: Tunnel, names: Sequence[Name]) -> None:
        """Lets go of `names` held by `tunnel`, and records it closed."""
        for name in names:
            self.registry.unbind(name, tunnel)
        for record in tunnel.records:
            self.record.tunnel_closed(record)
        tunnel.records.clear()

    async def _bind_all(self, raws: Sequence[str], tunnel: Tunnel, notify: Callable[[str], None]) -> list[Name]:
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

    def indexed(self, destination: Destination) -> bool:
        """Whether search engines may index what `destination` answers."""
        return indexed(self.indexing, getattr(destination, "index", None))

    async def authenticate(self, transport: str, credential: Credential, peer: Peer) -> Identity | None:
        """Who `credential` logs in as, if anyone, with every try recorded; a token denied lets no one in."""
        identity = await self.authenticator.authenticate(credential, peer)
        reason = None if identity is not None else REFUSED
        if identity is not None and identity.token in self.denied:
            identity, reason = None, DENIED
        elif identity is not None and not await self.users.admit(identity):
            identity, reason = None, NOT_A_USER
        self.record.auth(transport, METHODS[type(credential)], peer, identity, reason)
        return identity

    def open_session(
        self, identity: Identity, transport: str, peer: Peer, end: Callable[[str], None], client: dict[str, Any]
    ) -> Session:
        """A session for `identity`, recorded with what its client says of itself."""

        def ending(reason: str) -> None:
            session.reason = reason
            end(reason)

        session = self.sessions.open(identity, transport, peer, ending)
        self.record.session_opened(session, identity in self.policy.admins, client)
        return session

    def close_session(self, session: Session) -> None:
        self.sessions.close(session)
        self.record.session_closed(session, session.reason, session.ended_by)

    def deny(self, actor: Session, tokens: list[str], command: int | None = None) -> dict[str, Any]:
        """Stops `tokens` logging in from now on, and ends their sessions; only for an admin."""
        if actor.identity not in self.policy.admins:
            return {"error": "only an admin can deny tokens"}
        ended = []
        for token in dict.fromkeys(tokens):
            self.denied.add(token)
            self.record.deny(token, actor.identity)
            for session in self.sessions:
                if session.identity.token == token:
                    session.ended_by = command
                    session.end(f"its token was denied by {actor.identity.name}")
                    ended.append(session.id)
        return {"tokens": list(dict.fromkeys(tokens)), "ended": ended}

    def reach(self, actor: Session) -> dict[str, Any]:
        """Whether `actor` is an admin, and how far the server lets admins see and end sessions."""
        policy = self.policy
        return {
            "admin": actor.identity in policy.admins,
            "see": policy.see.name.lower(),
            "kick": policy.kick.name.lower(),
        }

    def kick(self, actor: Session, request: dict[str, Any], command: int | None = None) -> dict[str, Any]:
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
                session.ended_by = command
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

        def recorded(state: dict[str, Any]) -> None:
            for entry in lock.entries.values():
                self.record.credential(lock, entry)
            changed(state)

        try:
            lock, minted = build(spec, home, not plain, self.certs is not None, self.locking, recorded)
        except ValueError as exc:
            raise BindRejected(f"lock: {exc}") from None
        tunnel.lock = self.locks[lock.id] = lock
        self.record.lock_made(lock, tunnel.identity, lock_record(lock))
        return [{"label": label, "url": lock.link_url(key)} for label, key in minted]

    def unlock(self, tunnel: Tunnel) -> None:
        if (lock := tunnel.lock) is not None and self.locks.get(lock.id) is lock:
            del self.locks[lock.id]
            self.record.lock_ended(lock)

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

    def mint(self, actor: Identity, request: dict[str, Any], command: int | None = None) -> dict[str, Any]:
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
        taken = lock.link_labels()
        [label] = [str(request["label"])] if request.get("label") else next_links(taken, 1)
        if not LABEL.fullmatch(label) or label in taken:
            return {"error": f"{label!r} is taken or can't name a login"}
        expires, uses = request.get("expires"), request.get("uses", 1)
        if uses is not None and (type(uses) is not int or uses < 1):
            return {"error": "a link must be usable at least once"}
        key = lock.mint(label, host, path, expires if isinstance(expires, int) else None, uses)
        self.record.credential(lock, lock.entries[entry_id(LINK, label)], command)
        return {"label": label, "url": lock.link_url(key)}

    def end_login(self, actor: Identity, who: str) -> dict[str, Any]:
        """Ends `who`'s password or link in every locked tunnel of `actor`'s, logging out whoever used it."""
        ended = [self._held(tunnel) for tunnel, lock in self._locked(actor) if lock.end(who)]
        return {"who": who, "ended": ended}

    # Users

    def _acting(self, actor: Session, command: int | None) -> dict[str, Any]:
        """Who a change to users is by, and from where, as its events record it."""
        return {
            **acting(actor.identity), "session": actor.id, "transport": actor.transport, "address": actor.peer.host,
            "command": command,
        }  # fmt: skip

    async def user_listing(self, actor: Session) -> dict[str, Any]:
        """Every user, for an admin."""
        if actor.identity not in self.policy.admins:
            return {"error": "only an admin can list users"}
        return {"users": await self.users.listing(), "memory": self.users.memory}

    async def invite(self, actor: Session, request: dict[str, Any], command: int | None = None) -> dict[str, Any]:
        """A one-time code that lets someone set up their own login as a new user, or a forgotten one again."""
        if actor.identity not in self.policy.admins:
            return {"error": "only an admin can invite"}
        seconds = request.get("expires", INVITE_SECONDS)
        if type(seconds) is not int:
            return {"error": "an invite's expiry is in seconds"}
        name = str(request["name"])
        try:
            code, expires = await self.users.invite(name, self._acting(actor, command), seconds, command)
        except UserError as exc:
            return {"error": str(exc)}
        log.info("%s invited %s", actor.identity.user, name)
        return {"name": name, "code": code, "expires": expires, "memory": self.users.memory}

    async def set_admin(self, actor: Session, request: dict[str, Any], command: int | None = None) -> dict[str, Any]:
        """Makes a database user an admin, or not; an admin the settings make stays one."""
        if actor.identity not in self.policy.admins:
            return {"error": "only an admin can change who is one"}
        name, admin = str(request["name"]), bool(request["admin"])
        try:
            changed = await self.users.set_admin(name, admin, self._acting(actor, command))
        except UserError as exc:
            return {"error": str(exc)}
        # Still one by the settings' rules, whatever the database says.
        still = not admin and any(identity in self.policy.admins for identity in self.users.identities(name))
        return {"name": name, "admin": admin, "changed": changed, "still": still, "memory": self.users.memory}

    async def remove_user(self, actor: Session, request: dict[str, Any], command: int | None = None) -> dict[str, Any]:
        """Stops a database user logging in, and ends their sessions."""
        if actor.identity not in self.policy.admins:
            return {"error": "only an admin can remove users"}
        name = str(request["name"])
        try:
            await self.users.remove(name, self._acting(actor, command))
        except UserError as exc:
            return {"error": str(exc)}
        ended = []
        for session in self.sessions:
            if session.identity.user == name:
                session.ended_by = command
                session.end(f"{name} was removed by {actor.identity.user}")
                ended.append(session.id)
        log.info("%s removed %s", actor.identity.user, name)
        return {"name": name, "ended": ended}

    async def join(self, request: dict[str, Any], transport: str, peer: Peer) -> dict[str, Any]:
        """Sets up the login an invite is for, before any login: a password, a key, or both."""
        password = request.get("password")
        key = None
        if (line := request.get("public_key")) is not None:
            try:
                found = asyncssh.import_public_key(str(line))
            except asyncssh.KeyImportError, ValueError:
                return {"error": "that public key can't be read"}
            label = str(request.get("label") or found.get_comment() or "key")
            key = Key(found.export_public_key().decode().strip(), found.get_fingerprint(), label)
        hashed = None if password is None else await asyncio.to_thread(PasswordHasher().hash, str(password))
        alias = request.get("alias")
        context = {"by": "join", "transport": transport, "address": peer.host}
        try:
            name = await self.users.join(
                str(request["code"]), hashed, key, None if alias is None else str(alias), context
            )
        except UserError as exc:
            return {"error": str(exc)}
        log.info("%s joined from %s", name, peer.host)
        return {"name": name}


def lock_record(lock: Lock) -> dict[str, Any]:
    """A lock's settings as recorded: a page of its own by its digest, not the page."""
    settings = dataclasses.asdict(lock.settings)
    for page in PAGES:
        if settings[page]:
            settings[page] = hashlib.sha256(settings[page].encode()).hexdigest()
    return settings
