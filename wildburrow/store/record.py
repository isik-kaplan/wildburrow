"""What the server writes down as it runs, at the level WILDBURROW_DATABASE_RECORD asks for."""

import json
import logging
import zlib
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from wildburrow.core.types import Identity, Peer
from wildburrow.store.database import Database, Record

if TYPE_CHECKING:
    from wildburrow.core.locks import Entry, Lock
    from wildburrow.core.sessions import Session
    from wildburrow.edge.messages import Request

# The log lines kept, and the loggers whose lines would only be about writing them down.
LOG_LEVEL = logging.INFO
QUIET = ("wildburrow.store", "asyncio")
IN, OUT = "in", "out"
USER_AGENT = "user-agent"

# Rows another row points at before the batch carrying them is written get their id from the server; the rest from
# SQLite.
IDENTITIES = "SELECT method, subject, id FROM identities"
DENIED = "SELECT id FROM tokens WHERE revoked_at IS NOT NULL"
RUN = "INSERT INTO runs (id, version, hostname, domain, settings, started_at) VALUES (?, ?, ?, ?, ?, ?)"
RUN_STOPPED = "UPDATE runs SET stopped_at = ? WHERE id = ?"
LOG = "INSERT INTO logs (run_id, at, level, logger, message) VALUES (?, ?, ?, ?, ?)"
IDENTITY = (
    "INSERT INTO identities (id, method, subject, name, user_id, first_seen_at, last_seen_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)
IDENTITY_SEEN = "UPDATE identities SET name = ?, user_id = ?, last_seen_at = ? WHERE id = ?"
GRANT_USED = (
    "INSERT INTO tokens (id, identity_id, name, names, expires_at, first_used_at, last_used_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT (id) DO UPDATE SET identity_id = excluded.identity_id, last_used_at = excluded.last_used_at"
)
GRANT_DENIED = (
    "INSERT INTO tokens (id, revoked_at, revoked_by_identity_id) VALUES (?, ?, ?) "
    "ON CONFLICT (id) DO UPDATE SET revoked_at = excluded.revoked_at, "
    "revoked_by_identity_id = excluded.revoked_by_identity_id"
)
AUTH_ATTEMPT = (
    "INSERT INTO auth_attempts (run_id, at, transport, method, address, port, ok, identity_id, reason) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
SESSION = (
    "INSERT INTO sessions (id, run_id, identity_id, token_id, transport, admin, address, port, client_version, "
    "client_platform, expires_at, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
SESSION_GONE = "DELETE FROM sessions WHERE id = ?"
SESSION_ENDED = (
    "UPDATE sessions SET ended_at = ?, end_reason = coalesce(end_reason, ?), "
    "ended_by_command_id = coalesce(ended_by_command_id, ?) WHERE id = ?"
)
COMMAND = "INSERT INTO commands (id, session_id, at, kind, request) VALUES (?, ?, ?, ?, ?)"
ANSWERED = "UPDATE commands SET answer = ? WHERE id = ?"
TUNNEL = "INSERT INTO tunnels (id, session_id, lock_id, indexed, opened_at) VALUES (?, ?, ?, ?, ?)"
TUNNEL_REJECTED = (
    "INSERT INTO tunnels (id, session_id, indexed, opened_at, closed_at, rejected) VALUES (?, ?, 0, ?, ?, ?)"
)
TUNNEL_NAME = "INSERT INTO tunnel_names (tunnel_id, name, url) VALUES (?, ?, ?)"
TUNNEL_GONE = "DELETE FROM tunnels WHERE id = ?"
TUNNEL_CLOSED = "UPDATE tunnels SET closed_at = ? WHERE id = ?"
LOCK = (
    "INSERT INTO locks (id, identity_id, home, on_domain, settings, created_at) VALUES (?, ?, ?, ?, ?, ?) "
    "ON CONFLICT (id) DO UPDATE SET home = excluded.home, settings = excluded.settings, ended_at = NULL"
)
LOCK_GONE = "DELETE FROM locks WHERE id = ?"
LOCK_ENDED = "UPDATE locks SET ended_at = ? WHERE id = ?"
CREDENTIAL = (
    "INSERT INTO credentials (id, lock_id, kind, label, link_digest, link_host, link_path, max_uses, uses, "
    "last_used_at, logins, last_seen_at, expires_at, created_by_command_id, created_at, ended_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET "
    "uses = excluded.uses, last_used_at = excluded.last_used_at, logins = excluded.logins, "
    "last_seen_at = excluded.last_seen_at, ended_at = excluded.ended_at, "
    "created_by_command_id = coalesce(created_by_command_id, excluded.created_by_command_id)"
)
LINK_OPENED = "INSERT INTO link_opens (credential_id, at, address, user_agent, outcome) VALUES (?, ?, ?, ?, ?)"
LOGIN_ATTEMPT = (
    "INSERT INTO login_attempts (lock_id, at, via, label, credential_id, address, user_agent, ok, reason) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
HANDOFF = "INSERT INTO handoff_codes (digest, credential_id, host, created_at) VALUES (?, ?, ?, ?)"
REDEEMED = "UPDATE handoff_codes SET redeemed_at = ? WHERE digest = ?"
CONNECTION = "INSERT INTO connections (id, run_id, at, scheme, address, port, via_proxy) VALUES (?, ?, ?, ?, ?, ?, ?)"
CONNECTION_CLOSED = (
    "UPDATE connections SET tunnel_id = ?, bytes_in = ?, bytes_out = ?, duration_ms = ?, truncated = ? WHERE id = ?"
)
REQUEST = (
    "INSERT INTO requests (connection_id, at, method, host, path, query, user_agent, referer, lock_id, "
    "credential_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
TRAFFIC = (
    "INSERT INTO traffic (connection_id, seq, direction, at_ms, encoding, size, data) VALUES (?, ?, ?, ?, ?, ?, ?)"
)
CERTIFICATE = "INSERT INTO certificates (id, run_id, parent, requested_at) VALUES (?, ?, ?, ?)"
CERTIFICATE_FINISHED = "UPDATE certificates SET finished_at = ?, ok = ?, error = ? WHERE id = ?"
DNS_CHANGE = "INSERT INTO dns_changes (run_id, at, action, record, value, ok, error) VALUES (?, ?, ?, ?, ?, ?, ?)"


# What a login records itself as, among the events.
LOGGED_IN = {"by": "login"}


def acting(identity: Identity) -> dict[str, Any]:
    """Who an event is a change by: the user, and which of their identities."""
    return {"user": identity.user, "identity": identity.subject, "method": identity.method}


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def credential_id(lock: Lock, entry: Entry) -> str:
    return f"{lock.id}/{entry.id}"


def packed(data: bytes) -> tuple[str, bytes]:
    """`data` as stored: zlib'd when that comes out smaller, as text does; images and video stay raw."""
    squeezed = zlib.compress(data)
    return ("zlib", squeezed) if len(squeezed) < len(data) else ("raw", data)


class Recorder:
    """Writes the server's record; with no database, as in tests that don't look at it, writes nothing."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database
        self._identities: dict[tuple[str, str], int] = {}
        self.run_id: int | None = None
        # The id of the user an identity is, once the server's users are open.
        self.user_of: Callable[[Identity], int | None] = lambda identity: None
        level = None if database is None else database.storage.record
        # Whether what's over is kept, rather than going as it ends; and whether the bytes themselves are.
        self.history = level not in (None, Record.MINIMAL)
        self.traffic = level is Record.EVERYTHING
        self.traffic_max = 0 if database is None else database.storage.traffic_max

    def _write(self, sql: str, *params: Any) -> None:
        if self._database is not None:
            self._database.write(sql, *params)

    def _tracked(self, context: dict[str, Any], sql: str, *params: Any) -> None:
        """A write to a table whose changes are events, recorded as made for `context`."""
        if self._database is not None:
            self._database.write_for({"run": self.run_id, **context}, (sql, params))

    def _kept(self, sql: str, *params: Any) -> None:
        """A write only history wants."""
        if self.history:
            self._write(sql, *params)

    def _id(self, table: str) -> int:
        return 0 if self._database is None else self._database.next_id(table)

    def now(self) -> int:
        return 0 if self._database is None else self._database.now()

    # The server

    async def open(self, version: str, hostname: str, domain: str, settings: dict[str, Any]) -> set[str]:
        """Opens the record for a new run; the ids of the tokens denied in earlier ones."""
        if self._database is None:
            return set()
        await self._database.open()
        found = await self._database.read(IDENTITIES)
        self._identities = {(method, subject): identity_id for method, subject, identity_id in found}
        self.run_id = self._id("runs")
        # A run's id is the largest there plus one, as sqlite would give it, so nothing tells the two apart.
        self._write(RUN, self.run_id, version, hostname, domain, _json(settings), self.now())  # pragma: no mutate
        return {token for (token,) in await self._database.read(DENIED)}

    async def close(self) -> None:
        if self._database is None:
            return
        self._write(RUN_STOPPED, self.now(), self.run_id)
        await self._database.close()

    def log(self, record: logging.LogRecord) -> None:
        self._kept(LOG, self.run_id, int(record.created), record.levelname, record.name, record.getMessage())

    # Who connects

    def identity(self, identity: Identity) -> int:
        key = (identity.method, identity.subject)
        now = self.now()
        user = self.user_of(identity)
        if (found := self._identities.get(key)) is not None:
            self._tracked(LOGGED_IN, IDENTITY_SEEN, identity.name, user, now, found)
            return found
        self._identities[key] = found = self._id("identities")
        self._tracked(LOGGED_IN, IDENTITY, found, identity.method, identity.subject, identity.name, user, now, now)
        return found

    def auth(self, transport: str, method: str, peer: Peer, identity: Identity | None, reason: str | None) -> None:
        """A try at logging in to the server, and who it let in."""
        identity_id = None
        if identity is not None:
            identity_id = self.identity(identity)
            if identity.token:
                names = None if identity.names is None else _json(list(identity.names))
                now = self.now()
                self._write(GRANT_USED, identity.token, identity_id, identity.name, names, identity.expires, now, now)
        self._kept(
            AUTH_ATTEMPT, self.run_id, self.now(), transport, method, peer.host, peer.port, int(identity is not None),
            identity_id, reason,
        )  # fmt: skip

    def deny(self, token: str, by: Identity) -> None:
        self._tracked(acting(by), GRANT_DENIED, token, self.now(), self.identity(by))

    def session_opened(self, session: Session, admin: bool, client: dict[str, Any]) -> None:
        identity_id = self.identity(session.identity)
        self._write(
            SESSION, session.id, self.run_id, identity_id, session.identity.token or None, session.transport,
            int(admin), session.peer.host, session.peer.port, client.get("version"), client.get("platform"),
            session.identity.expires, session.since,
        )  # fmt: skip

    def session_closed(self, session: Session, reason: str | None, command: int | None = None) -> None:
        if not self.history:
            self._write(SESSION_GONE, session.id)
            return
        self._write(SESSION_ENDED, self.now(), reason, command, session.id)

    def command(self, session: Session, kind: str, request: dict[str, Any]) -> int | None:
        """A command as it comes in, before it's answered."""
        if not self.history:
            return None
        command = self._id("commands")
        self._write(COMMAND, command, session.id, self.now(), kind, _json(request))
        return command

    def answered(self, command: int | None, answer: dict[str, Any]) -> None:
        if command is not None:
            self._write(ANSWERED, _json(answer), command)

    # Tunnels and locks

    def tunnel_opened(self, session: Session, lock: Lock | None, indexed: bool, urls: dict[str, str]) -> int:
        tunnel = self._id("tunnels")
        self._write(TUNNEL, tunnel, session.id, None if lock is None else lock.id, int(indexed), self.now())
        for name, url in urls.items():
            self._write(TUNNEL_NAME, tunnel, name, url)
        return tunnel

    def tunnel_rejected(self, session: Session, names: list[str], reason: str) -> None:
        if not self.history:
            return
        tunnel, now = self._id("tunnels"), self.now()
        self._write(TUNNEL_REJECTED, tunnel, session.id, now, now, reason)
        for name in dict.fromkeys(names):
            self._write(TUNNEL_NAME, tunnel, name, None)

    def tunnel_closed(self, tunnel: int) -> None:
        if not self.history:
            self._write(TUNNEL_GONE, tunnel)
            return
        self._write(TUNNEL_CLOSED, self.now(), tunnel)

    def lock_made(self, lock: Lock, identity: Identity, settings: dict[str, Any]) -> None:
        """A lock, new or brought back by a reconnect, and everyone it lets in."""
        self._write(LOCK, lock.id, self.identity(identity), lock.home, int(lock.on_domain), _json(settings), self.now())
        for entry in lock.entries.values():
            self.credential(lock, entry)

    def lock_ended(self, lock: Lock) -> None:
        if not self.history:
            self._write(LOCK_GONE, lock.id)
            return
        self._write(LOCK_ENDED, self.now(), lock.id)

    def credential(self, lock: Lock, entry: Entry, command: int | None = None) -> None:
        """One password or link as it stands, made the first time it's seen."""
        link = entry.key or None
        self._write(
            CREDENTIAL, credential_id(lock, entry), lock.id, entry.kind, entry.label, link, entry.host or None,
            entry.path if link else None, entry.uses if link else None, entry.spent, entry.used, entry.logins,
            entry.seen, entry.expires, command, self.now(), self.now() if entry.ended else None,
        )  # fmt: skip

    def link_opened(self, lock: Lock, entry: Entry, peer: Peer, request: Request, used: bool) -> None:
        outcome = "used" if used else "shown"
        self._kept(LINK_OPENED, credential_id(lock, entry), self.now(), peer.host, request.header(USER_AGENT), outcome)

    def login_attempt(
        self, lock: Lock, via: str, label: str | None, entry: Entry | None, peer: Peer, request: Request,
        reason: str | None,
    ) -> None:  # fmt: skip
        credential = None if entry is None else credential_id(lock, entry)
        self._kept(
            LOGIN_ATTEMPT, lock.id, self.now(), via, label, credential, peer.host, request.header(USER_AGENT),
            int(reason is None), reason,
        )  # fmt: skip

    def handoff(self, lock: Lock, entry: Entry, digest: str, host: str) -> None:
        self._kept(HANDOFF, digest, credential_id(lock, entry), host, self.now())

    def redeemed(self, digest: str) -> None:
        self._kept(REDEEMED, self.now(), digest)

    # Visitors

    def connection_opened(self, scheme: str, peer: Peer, via_proxy: str | None) -> int | None:
        if not self.history:
            return None
        connection = self._id("connections")
        self._write(CONNECTION, connection, self.run_id, self.now(), scheme, peer.host, peer.port, via_proxy)
        return connection

    def connection_closed(
        self, connection: int, tunnel: int | None, bytes_in: int, bytes_out: int, duration_ms: int, truncated: bool
    ) -> None:
        self._write(CONNECTION_CLOSED, tunnel, bytes_in, bytes_out, duration_ms, int(truncated), connection)

    def request(
        self, connection: int, request: Request, lock: Lock | None, entry: Entry | None, status: int | None
    ) -> None:
        credential = None if lock is None or entry is None else credential_id(lock, entry)
        self._write(
            REQUEST, connection, self.now(), request.method, request.host, _path(request.path()),
            request.query() or None, request.header(USER_AGENT), request.header("referer"),
            None if lock is None else lock.id, credential, status,
        )  # fmt: skip

    def traffic_chunk(self, connection: int, seq: int, direction: str, at_ms: int, data: bytes) -> None:
        encoding, stored = packed(data)
        self._write(TRAFFIC, connection, seq, direction, at_ms, encoding, len(data), stored)

    # Certificates and DNS

    def certificate_requested(self, parent: str) -> int | None:
        if not self.history:
            return None
        certificate = self._id("certificates")
        self._write(CERTIFICATE, certificate, self.run_id, parent, self.now())
        return certificate

    def certificate_finished(self, certificate: int, error: str | None) -> None:
        self._write(CERTIFICATE_FINISHED, self.now(), int(error is None), error, certificate)

    def dns_change(self, action: str, record: str, value: str | None, error: str | None) -> None:
        self._kept(DNS_CHANGE, self.run_id, self.now(), action, record, value, int(error is None), error)


def _path(path: str) -> str:
    """`path` with any link key cut out, so the record can't open a link."""
    head, sep, _ = path.partition("/link/")
    return head + sep


class Handler(logging.Handler):
    """Keeps the server's log lines in the record, leaving out the record's own."""

    def __init__(self, recorder: Recorder) -> None:
        super().__init__(LOG_LEVEL)
        self._recorder = recorder

    def emit(self, record: logging.LogRecord) -> None:
        if not record.name.startswith(QUIET):
            self._recorder.log(record)
