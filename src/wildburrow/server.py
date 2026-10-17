import asyncio
import contextlib
import logging
import signal
from collections.abc import Mapping
from datetime import timedelta
from typing import Any, Self

from wildburrow import config, plugins
from wildburrow.auth.base import Authenticator
from wildburrow.certs.acme import ACMEIssuer
from wildburrow.certs.manager import CertManager, server_context
from wildburrow.certs.store import CertStore
from wildburrow.core.context import ServerContext
from wildburrow.core.names import LABEL
from wildburrow.edge import proxy
from wildburrow.edge.http import Edge, Mode

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
        self.ctx = ServerContext(
            domain=domain,
            max_depth=settings.max_depth,
            data_dir=settings.data_dir,
            authenticator=Authenticator([plugins.load("auth", name, env) for name in settings.auth]),
        )
        self.transports: list[Any] = [plugins.load("transport", name, env) for name in settings.transports]
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
        issuer = ACMEIssuer(
            settings.acme_directory,
            settings.acme_email,
            settings.data_dir / "acme",
            self.dns,
            settings.acme_propagation_seconds,
            settings.acme_timeout_seconds,
        )
        certs = CertManager(
            self.ctx.domain,
            CertStore(settings.data_dir / "certs"),
            issuer,
            self.dns,
            settings.dns_manage_records,
            timedelta(days=settings.renew_before_days),
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
            if self.dns is not None:
                in_use = lambda: {certs.parent(name) for name in self.ctx.registry.names()}  # noqa: E731
                maintain = certs.maintain(in_use, self.settings.renew_interval_seconds, CERT_RETRY_SECONDS)
                stack.push_async_callback(_cancel, asyncio.create_task(maintain))
            self._stack = stack.pop_all()
        log.info("serving *.%s", self.ctx.domain)
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._stack.aclose()


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
