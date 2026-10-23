import asyncio
import logging
import re
import ssl
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus

from wildburrow import protocol
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import TunnelUnavailable
from wildburrow.core.names import host_labels
from wildburrow.core.types import Peer, bound_port
from wildburrow.edge import proxy
from wildburrow.streams import relay

log = logging.getLogger(__name__)

HEAD_END = b"\r\n\r\n"
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
VERSION = re.compile(r"HTTP/1\.[01]")
WHITESPACE = " \t"
TEXT = "text/plain; charset=utf-8"
JSON = "application/json"


class BadRequest(Exception):
    pass


class Mode(Enum):
    PROXY = "proxy"
    REDIRECT = "redirect"


@dataclass(frozen=True, slots=True)
class Request:
    host: str
    target: str


def parse_request(head: bytes) -> Request:
    if not head.isascii():
        raise BadRequest("non-ascii request head")
    text = head.decode()
    request_line, *header_lines = text.removesuffix("\r\n\r\n").split("\r\n")
    parts = request_line.split(" ")
    if len(parts) != 3 or not TOKEN.fullmatch(parts[0]) or not VERSION.fullmatch(parts[2]):
        raise BadRequest("malformed request line")
    if not parts[1].startswith("/"):
        raise BadRequest("only origin-form request targets are accepted")
    hosts = []
    for line in header_lines:
        name, sep, value = line.partition(":")
        if not sep or not TOKEN.fullmatch(name):
            raise BadRequest("malformed header line")
        if name.lower() == "host":
            hosts.append(value.strip(WHITESPACE))
    if len(hosts) != 1:
        raise BadRequest("exactly one Host header is required")
    host, _, port = hosts[0].partition(":")
    if port and not port.isdigit():
        raise BadRequest("malformed Host port")
    return Request(host.lower(), parts[1])


def response(
    status: HTTPStatus, headers: dict[str, str] | None = None, body: bytes | None = None, content_type: str = TEXT
) -> bytes:
    body = f"{status.value} {status.phrase}\n".encode() if body is None else body
    lines = [f"HTTP/1.1 {status.value} {status.phrase}"]
    lines += [f"{key}: {value}" for key, value in (headers or {}).items()]
    lines += [f"Content-Length: {len(body)}", f"Content-Type: {content_type}", "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


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
        try:
            peer = await self._accept(reader, writer)
            if peer is None:
                return
            reply = await self._serve(peer, reader, writer)
            if reply is not None:
                writer.write(reply)
                await writer.drain()
        except OSError:
            pass
        finally:
            self._handlers.discard(handler)
            writer.close()

    async def _serve(self, peer: Peer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes | None:
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
            request = parse_request(head)
        except BadRequest as exc:
            log.info("bad request from %s: %s", peer.host, exc)
            return response(HTTPStatus.BAD_REQUEST)

        if self._tls is not None:
            presented = writer.get_extra_info("ssl_object").context
            if presented is not self._ctx.certs.context_for(request.host):  # type: ignore[union-attr]
                return response(HTTPStatus.MISDIRECTED_REQUEST)
        labels = host_labels(request.host, self._ctx.domain)
        # Any host but a tunnel's, so a tunnel's own app keeps every path.
        if labels is None and request.target == protocol.INFO_PATH:
            return response(HTTPStatus.OK, body=self._ctx.info, content_type=JSON)
        if labels is not None:
            tunnel = self._ctx.registry.resolve(labels)
        else:
            tunnel = self._ctx.root if request.host == self._ctx.domain else None
        if tunnel is None:
            return response(HTTPStatus.NOT_FOUND)
        if self._mode is Mode.REDIRECT:
            return response(HTTPStatus.PERMANENT_REDIRECT, {"Location": f"https://{request.host}{request.target}"})

        try:
            upstream = await tunnel.open_stream(peer)
        except TunnelUnavailable as exc:
            log.info("could not reach the client for %s: %s", request.host, exc)
            return response(HTTPStatus.BAD_GATEWAY)
        upstream[1].write(head)
        await upstream[1].drain()
        await relay((reader, writer), upstream)
        return None
