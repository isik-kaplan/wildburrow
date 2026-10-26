import asyncio
import dataclasses
import logging
import ssl
from enum import Enum
from http import HTTPStatus

from wildburrow import protocol
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import TunnelUnavailable
from wildburrow.core.locks import Lock
from wildburrow.core.names import host_labels
from wildburrow.core.types import Destination, Peer, bound_port
from wildburrow.edge import gate, proxy
from wildburrow.edge.exchange import Answer, Exchange, Forward, ReadBody, status_of
from wildburrow.edge.messages import HEAD_END, JSON, BadRequest, Request, parse_request, response
from wildburrow.edge.watch import Counted, Watch
from wildburrow.store.record import OUT

log = logging.getLogger(__name__)


class Mode(Enum):
    PROXY = "proxy"
    REDIRECT = "redirect"


class Edge:
    def __init__(
        self,
        ctx: ServerContext,
        host: str,
        port: int,
        max_header_bytes: int,
        header_timeout: float,
        mode: Mode = Mode.PROXY,
        tls: ssl.SSLContext | None = None,
        proxy_from: list[proxy.Network] | None = None,
    ) -> None:
        self._ctx = ctx
        self._host = host
        self._port = port
        self._max_header_bytes = max_header_bytes
        self._header_timeout = header_timeout
        self._mode = mode
        self._tls = tls
        self._proxy_from = proxy_from
        self._scheme = "http" if tls is None else "https"
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task[None]] = set()

    @property
    def port(self) -> int:
        return bound_port(self._server)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._port, limit=self._max_header_bytes)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server.close_clients()
            await self._server.wait_closed()
        # Closing a connection doesn't end a handler still waiting on its tunnel.
        for handler in list(self._handlers):
            handler.cancel()
        await asyncio.gather(*self._handlers, return_exceptions=True)

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Peer | None:
        peer = Peer(*writer.get_extra_info("peername")[:2])
        if self._proxy_from is not None:
            if not proxy.trusted(peer.host, self._proxy_from):
                log.warning("refusing a PROXY protocol connection from untrusted %s", peer.host)
                return None
            try:
                async with asyncio.timeout(self._header_timeout):
                    peer = await proxy.read_header(reader, peer)
            except (proxy.ProxyHeaderError, asyncio.IncompleteReadError, TimeoutError) as exc:
                log.info("bad PROXY protocol header from %s: %s", peer.host, exc)
                return None
        if self._tls is not None:
            try:
                await writer.start_tls(self._tls, ssl_handshake_timeout=self._header_timeout)
            except OSError, TimeoutError:
                return None
        return peer

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handler = asyncio.current_task()
        assert handler is not None  # noqa: S101
        self._handlers.add(handler)
        watch = None
        try:
            peer = await self._accept(reader, writer)
            if peer is None:
                return
            arrived = Peer(*writer.get_extra_info("peername")[:2])
            via = None if self._proxy_from is None else arrived.host
            watch = Watch(self._ctx.record, self._ctx.record.connection_opened(self._scheme, peer, via))
            reply = await self._serve(peer, reader, writer, watch)
            if reply is not None:
                if watch.request is not None:
                    watch.answered(watch.request, None, status_of(reply))
                Counted(writer, OUT, watch).write(reply)
                await writer.drain()
        except OSError:
            pass
        finally:
            self._handlers.discard(handler)
            if watch is not None:
                watch.closed()
            writer.close()

    async def _body(self, reader: asyncio.StreamReader, size: int) -> bytes:
        async with asyncio.timeout(self._header_timeout):
            return await reader.readexactly(size)

    async def _serve(
        self, peer: Peer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, watch: Watch
    ) -> bytes | None:
        try:
            async with asyncio.timeout(self._header_timeout):
                head = await reader.readuntil(HEAD_END)
        except asyncio.LimitOverrunError:
            return response(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE)
        except asyncio.IncompleteReadError:
            return None
        except TimeoutError:
            return response(HTTPStatus.REQUEST_TIMEOUT)
        try:
            request = dataclasses.replace(parse_request(head), peer=peer)
        except BadRequest as exc:
            log.info("bad request from %s: %s", peer.host, exc)
            return response(HTTPStatus.BAD_REQUEST)
        watch.request = request

        if self._tls is not None:
            presented = writer.get_extra_info("ssl_object").context
            if presented is not self._ctx.certs.context_for(request.host):  # type: ignore[union-attr]
                return response(HTTPStatus.MISDIRECTED_REQUEST)
        labels = host_labels(request.host, self._ctx.domain)
        # Any host but a tunnel's, so a tunnel's own app keeps every path.
        if labels is None and request.target == protocol.INFO_PATH:
            return response(HTTPStatus.OK, body=self._ctx.info, content_type=JSON)
        own = labels is None and request.host == self._ctx.domain
        homes = own and request.path().startswith(protocol.LOCK_PATH)
        tunnel: Destination | None
        if labels is not None:
            tunnel = held = self._ctx.registry.resolve(labels)
            lock = None if held is None else held.lock
        else:
            tunnel, lock = self._ctx.root if own else None, None
        if tunnel is None and not homes:
            return response(HTTPStatus.NOT_FOUND)
        watch.lock = lock
        if records := getattr(tunnel, "records", None):
            watch.tunnel = records[-1]
        if self._mode is Mode.REDIRECT:
            return response(HTTPStatus.PERMANENT_REDIRECT, {"Location": f"https://{request.host}{request.target}"})
        body = lambda size: self._body(reader, size)  # noqa: E731
        if homes:
            return await gate.home(self._ctx, request, body)
        entry = None
        if lock is not None:
            outcome = await gate.guard(self._ctx, lock, request, body)
            if isinstance(outcome, bytes):
                return outcome
            head, entry = outcome.head, outcome.entry

        try:
            upstream = await tunnel.open_stream(peer)
        except TunnelUnavailable as exc:
            log.info("could not reach the client for %s: %s", request.host, exc)
            return response(HTTPStatus.BAD_GATEWAY)
        admit = lambda later, as_sent, read: self._admit(later, as_sent, read, request, lock)  # noqa: E731
        tag = not self._ctx.indexed(tunnel)
        exchange = Exchange(
            (reader, writer), upstream, limit=self._max_header_bytes, tag=tag, admit=admit, refuse=response,
            watch=watch,
        )  # fmt: skip
        watch.request = None
        await exchange.run(head, request, entry)
        return None

    async def _admit(
        self, request: Request, head: bytes, read: ReadBody, first: Request, lock: Lock | None
    ) -> Forward | Answer:
        """A later request on the connection, held to the first one's host and checked by its lock."""
        if request.host != first.host:
            # Another host is another tunnel, which its own connection reaches.
            return Answer(response(HTTPStatus.MISDIRECTED_REQUEST))
        if lock is None:
            return Forward(head)
        outcome = await gate.guard(self._ctx, lock, dataclasses.replace(request, peer=first.peer), read)
        return Answer(outcome) if isinstance(outcome, bytes) else Forward(outcome.head, outcome.entry)
