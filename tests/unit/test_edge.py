import asyncio
import contextlib
import ipaddress
import logging
import ssl
from collections.abc import AsyncIterator

import pytest

from tests.unit.test_http import Reader, Writer
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import TunnelUnavailable
from wildburrow.core.types import Peer
from wildburrow.edge.http import Edge

LOOPBACK = [ipaddress.ip_network("127.0.0.0/8")]
REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
REPLY = b"HTTP/1.1 204 No Content\r\n\r\n"


class Root:
    def __init__(self, failure: Exception | None = None) -> None:
        self.peers: list[Peer] = []
        self.failure = failure

    async def open_stream(self, peer: Peer) -> tuple[Reader, Writer]:
        if self.failure is not None:
            raise self.failure
        self.peers.append(peer)
        return Reader(REPLY), Writer()


@contextlib.asynccontextmanager
async def running(ctx: ServerContext, host: str = "127.0.0.1", **options: object) -> AsyncIterator[Edge]:
    settings = {"max_header_bytes": 1024, "header_timeout": 0.2} | options
    edge = Edge(ctx, host, 0, **settings)
    await edge.start()
    try:
        yield edge
    finally:
        await edge.stop()


async def exchange(host: str, port: int, data: bytes) -> tuple[bytes, int]:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(data)
    reply = b""
    async with asyncio.timeout(2):
        with contextlib.suppress(ConnectionResetError):
            reply = await reader.read()
    local_port = writer.get_extra_info("sockname")[1]
    writer.close()
    return reply, local_port


class Stalled:
    """A tunnel that never opens, as one whose client went away mid-request."""

    def __init__(self) -> None:
        self.waiting = asyncio.Event()

    async def open_stream(self, peer: Peer) -> tuple[Reader, Writer]:
        self.waiting.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


def handlers() -> list[asyncio.Task]:
    return [task for task in asyncio.all_tasks() if "Edge._handle" in repr(task)]


async def test_stopping_ends_requests_still_waiting_on_a_tunnel(ctx: ServerContext) -> None:
    ctx.root = stalled = Stalled()
    async with running(ctx) as edge:
        reader, writer = await asyncio.open_connection("127.0.0.1", edge.port)
        writer.write(REQUEST)
        async with asyncio.timeout(2):
            await stalled.waiting.wait()
        assert len(handlers()) == 1
    assert handlers() == []
    assert edge._handlers == set()
    async with asyncio.timeout(2):
        assert await reader.read() == b""
    writer.close()


async def test_finished_requests_leave_no_handler_behind(ctx: ServerContext) -> None:
    ctx.root = Root()
    async with running(ctx) as edge:
        assert (await exchange("127.0.0.1", edge.port, REQUEST))[0] == REPLY
        async with asyncio.timeout(2):
            while edge._handlers:
                await asyncio.sleep(0.01)


async def test_the_edge_listens_only_where_it_is_told(ctx: ServerContext) -> None:
    async with running(ctx) as edge:
        assert [sock.getsockname()[0] for sock in edge._server.sockets] == ["127.0.0.1"]


async def test_ipv6_visitors_reach_the_tunnel(ctx: ServerContext) -> None:
    ctx.root = root = Root()
    async with running(ctx, "::1") as edge:
        reply, port = await exchange("::1", edge.port, REQUEST)
    assert reply == REPLY
    assert root.peers == [Peer("::1", port)]


async def test_the_header_limit_is_the_configured_one(ctx: ServerContext) -> None:
    async with running(ctx) as edge:
        reply, _ = await exchange("127.0.0.1", edge.port, b"GET / HTTP/1.1\r\nX: " + b"a" * 2000 + b"\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 431 ")


async def test_a_silent_proxy_is_dropped_after_the_header_timeout(ctx: ServerContext) -> None:
    async with running(ctx, proxy_from=LOOPBACK) as edge:
        assert (await exchange("127.0.0.1", edge.port, b""))[0] == b""


async def test_a_silent_tls_client_is_dropped_after_the_header_timeout(ctx: ServerContext) -> None:
    async with running(ctx, tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)) as edge:
        assert (await exchange("127.0.0.1", edge.port, b""))[0] == b""


async def test_an_unknown_proxied_address_falls_back_to_the_proxy(ctx: ServerContext) -> None:
    ctx.root = root = Root()
    async with running(ctx, proxy_from=LOOPBACK) as edge:
        reply, port = await exchange("127.0.0.1", edge.port, b"PROXY UNKNOWN\r\n" + REQUEST)
    assert reply == REPLY
    assert root.peers == [Peer("127.0.0.1", port)]


@pytest.mark.parametrize(
    ("allowed", "data", "level", "message"),
    [
        ([ipaddress.ip_network("10.0.0.0/8")], REQUEST, logging.WARNING,
         "refusing a PROXY protocol connection from untrusted 127.0.0.1"),
        (LOOPBACK, b"PROXY TCP4 x\r\n", logging.INFO,
         "bad PROXY protocol header from 127.0.0.1: malformed PROXY v1 header"),
    ],
)  # fmt: skip
async def test_refused_proxy_connections_are_logged(
    ctx: ServerContext, caplog: pytest.LogCaptureFixture, allowed: list, data: bytes, level: int, message: str
) -> None:
    caplog.set_level(logging.INFO)
    ctx.root = Root()
    async with running(ctx, proxy_from=allowed) as edge:
        assert (await exchange("127.0.0.1", edge.port, data))[0] == b""
    assert caplog.record_tuples == [("wildburrow.edge.http", level, message)]


@pytest.mark.parametrize(
    ("root", "data", "status", "message"),
    [
        (
            Root(),
            b"GET / HTTP/9\r\nHost: example.com\r\n\r\n",
            400,
            "bad request from 127.0.0.1: malformed request line",
        ),
        (Root(TunnelUnavailable("gone")), REQUEST, 502, "could not reach the client for example.com: gone"),
    ],
)
async def test_failed_requests_are_logged(
    ctx: ServerContext, caplog: pytest.LogCaptureFixture, root: Root, data: bytes, status: int, message: str
) -> None:
    caplog.set_level(logging.INFO)
    ctx.root = root
    async with running(ctx) as edge:
        reply, _ = await exchange("127.0.0.1", edge.port, data)
    assert reply.startswith(f"HTTP/1.1 {status} ".encode())
    assert caplog.record_tuples == [("wildburrow.edge.http", logging.INFO, message)]
