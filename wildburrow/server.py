import asyncio
import contextlib
import dataclasses
import json
import logging
import signal
import socket
from collections.abc import Mapping
from datetime import timedelta
from importlib.metadata import version
from typing import Any, Self

from wildburrow import config, durations, plugins
from wildburrow.auth.base import Authenticator
from wildburrow.certs.acme import ACMEIssuer
from wildburrow.certs.manager import CertManager, server_context
from wildburrow.certs.store import CertStore
from wildburrow.core import indexing
from wildburrow.core.context import ServerContext
from wildburrow.core.locks import Locking
from wildburrow.core.names import LABEL
from wildburrow.core.sessions import Admins, Policy, level
from wildburrow.dns.recorded import RecordedDNS
from wildburrow.edge import proxy
from wildburrow.edge.http import Edge, Mode
from wildburrow.locks import FIELDS, LOCK_PREFIX, LockSettings, ServerLockSettings, problems
from wildburrow.store.database import DATABASE_PREFIX, Database, DatabaseError, DatabaseSettings, storage
from wildburrow.store.record import Handler, Recorder

log = logging.getLogger(__name__)

CERT_RETRY_SECONDS = 300


class Server:
    def __init__(self, settings: config.ServerSettings, env: Mapping[str, str]) -> None:
        domain = settings.domain.lower()
        if not all(LABEL.fullmatch(label) for label in domain.split(".")):
            raise config.ConfigError(f"{config.PREFIX}DOMAIN: {settings.domain!r} is not a valid domain")
        if not settings.auth or not settings.transports:
            raise config.ConfigError(f"{config.PREFIX}AUTH and {config.PREFIX}TRANSPORTS need at least one plugin each")
        try:
            self._proxy_from = proxy.networks(settings.proxy_trusted)
        except ValueError as exc:
            raise config.ConfigError(f"{config.PREFIX}PROXY_TRUSTED: {exc}") from None
        self.settings = settings
        authenticator = Authenticator([plugins.load("auth", name, env) for name in settings.auth])
        self.ctx = ServerContext(
            domain=domain,
            max_depth=settings.max_depth,
            data_dir=settings.data_dir,
            authenticator=authenticator,
            policy=policy(settings, authenticator),
            locking=locking(env),
            indexing=indexing.parse(f"{config.PREFIX}INDEX", settings.index),
            record=Recorder(Database(storage(settings.database, config.load(DatabaseSettings, env, DATABASE_PREFIX)))),
        )
        self.loaded: dict[str, Any] = {name: plugins.load("transport", name, env) for name in settings.transports}
        self.transports: list[Any] = list(self.loaded.values())
        self.offered = {name: self.ctx.authenticator.methods(loaded.methods) for name, loaded in self.loaded.items()}
        self.defaults = client_defaults(settings, self.offered)
        self.dns: Any = plugins.load("dns", settings.dns, env) if settings.dns else None
        self.edges: list[Edge]
        self._stack: contextlib.AsyncExitStack

    def _edge(self, port: int, proxied: bool, mode: Mode = Mode.PROXY, host: str = "", tls: Any = None) -> Edge:
        settings = self.settings
        return Edge(
            self.ctx,
            host or settings.http_host,
            port,
            settings.max_header_bytes,
            settings.header_timeout,
            mode,
            tls,
            self._proxy_from if proxied else None,
        )

    def _setup_tls(self) -> CertManager:
        settings = self.settings
        recorded = RecordedDNS(self.dns, self.ctx.record)
        issuer = ACMEIssuer(
            settings.acme_directory,
            settings.acme_email,
            settings.data_dir / "acme",
            recorded,
            settings.acme_propagation_seconds,
            settings.acme_timeout_seconds,
        )
        certs = CertManager(
            self.ctx.domain,
            CertStore(settings.data_dir / "certs"),
            issuer,
            recorded,
            settings.dns_manage_records,
            timedelta(days=settings.renew_before_days),
            record=self.ctx.record,
        )
        self.ctx.certs = certs
        tls = server_context()
        tls.sni_callback = certs.sni_callback
        self.edges = [
            self._edge(settings.http_port, settings.http_proxy_protocol, Mode.REDIRECT),
            self._edge(settings.https_port, settings.https_proxy_protocol, host=settings.https_host, tls=tls),
        ]
        return certs

    async def __aenter__(self) -> Self:
        self.settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        async with contextlib.AsyncExitStack() as stack:
            record = self.ctx.record
            try:
                denied = await record.open(
                    version(__package__), socket.gethostname(), self.ctx.domain, recorded(self.settings)
                )
            except DatabaseError as exc:
                raise config.ConfigError(f"{config.PREFIX}DATABASE: {exc}") from None
            stack.push_async_callback(record.close)
            self.ctx.denied = denied
            handler = Handler(record)
            logging.getLogger(__package__).addHandler(handler)
            stack.callback(logging.getLogger(__package__).removeHandler, handler)
            if self.dns is not None:
                stack.push_async_callback(self.dns.aclose)
                certs = self._setup_tls()
            else:
                self.edges = [self._edge(self.settings.http_port, self.settings.http_proxy_protocol)]
            for edge in self.edges:
                await edge.start()
                stack.push_async_callback(edge.stop)
            for transport in self.transports:
                await transport.start(self.ctx)
                stack.push_async_callback(transport.stop)
            self.ctx.info = json.dumps(self.info()).encode()
            if self.dns is not None:
                in_use = lambda: {certs.parent(name) for name in self.ctx.registry.names()}  # noqa: E731
                maintain = certs.maintain(in_use, self.settings.renew_interval_seconds, CERT_RETRY_SECONDS)
                stack.push_async_callback(_cancel, asyncio.create_task(maintain))
            self._stack = stack.pop_all()
        log.info("serving *.%s", self.ctx.domain)
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._stack.aclose()

    def info(self) -> dict[str, Any]:
        """How to log in, for `wildburrow login`: what each transport takes, and where a client should start."""
        transports = {name: {"auth": self.offered[name], **loaded.published()} for name, loaded in self.loaded.items()}
        return {"version": version(__package__), "transports": transports, "defaults": self.defaults}


def recorded(settings: config.ServerSettings) -> dict[str, Any]:
    """The settings a run is recorded with, secrets only as set."""
    found = {}
    for field in dataclasses.fields(settings):
        value = getattr(settings, field.name)
        found[field.name] = ("(set)" if value else "") if field.metadata.get(config.SECRET) else value
    return json.loads(json.dumps(found, default=str))


def policy(settings: config.ServerSettings, authenticator: Authenticator) -> Policy:
    """Who is an admin, and how far anyone sees and ends other sessions."""
    admins = Admins.parse(f"{config.PREFIX}ADMINS", settings.admins, settings.auth, authenticator.signers())
    see, kick = level(f"{config.PREFIX}SEE", settings.see), level(f"{config.PREFIX}KICK", settings.kick)
    return Policy(admins, see, kick)


def locking(env: Mapping[str, str]) -> Locking:
    """What every lock starts from, as the operator set it."""
    loaded = config.load(ServerLockSettings, env, LOCK_PREFIX)
    found = problems(loaded, lambda name: f"{LOCK_PREFIX}{name.upper()}")
    if (code_seconds := durations.seconds(loaded.code_expires)) is None:
        found.append(
            f"{LOCK_PREFIX}CODE_EXPIRES: expected a duration {durations.EXAMPLES}, got {loaded.code_expires!r}"
        )
    if loaded.attempts < 1:
        found.append(f"{LOCK_PREFIX}ATTEMPTS: must be at least 1")
    if found:
        raise config.ConfigError("; ".join(found))
    settings = LockSettings(**{name: getattr(loaded, name) for name in FIELDS})
    return Locking(settings, loaded.attempts, code_seconds)


def client_defaults(settings: config.ServerSettings, offered: Mapping[str, list[str]]) -> dict[str, str]:
    """The operator's choice, or else the first transport that can log anyone in and its first method."""
    usable = [name for name, methods in offered.items() if methods]
    if not usable:
        raise config.ConfigError(f"no {config.PREFIX}AUTH plugin works over any of {config.PREFIX}TRANSPORTS")
    transport = settings.suggested_transport or usable[0]
    if transport not in usable:
        raise config.ConfigError(
            f"{config.PREFIX}SUGGESTED_TRANSPORT: {transport!r} isn't one of the transports clients can log in over: "
            + ", ".join(usable)
        )
    methods = offered[transport]
    auth = settings.suggested_auth or methods[0]
    if auth not in methods:
        raise config.ConfigError(
            f"{config.PREFIX}SUGGESTED_AUTH: {auth!r} doesn't work over {transport}, which takes: " + ", ".join(methods)
        )
    return {"transport": transport, "auth": auth}


async def _cancel(task: asyncio.Task[None]) -> None:
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def serve(env: Mapping[str, str]) -> None:
    server = Server(config.load(config.ServerSettings, env, config.PREFIX), env)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    async with server:
        await stop.wait()
