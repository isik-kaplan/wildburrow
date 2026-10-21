import asyncio
import contextlib
import functools
import ssl
from collections.abc import AsyncIterator, Callable

import pytest
from websockets.asyncio.client import connect as ws_connect
from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosedOK

from tests import acme_env
from tests.conftest import DOMAIN, TIMEOUT, Connect, Credentials, Running, StartServer
from tests.e2e.test_websocket import TOKEN, client_config, start_client, stop
from wildburrow.tokens import digest

pytestmark = pytest.mark.e2e

NAME = "echo"
HOST = f"{NAME}.{DOMAIN}"
ORIGIN = f"https://{HOST}"
TUNNELS = [("ssh", "key"), ("ssh", "password"), ("websocket", "key"), ("websocket", "password"), ("websocket", "token")]
ENV = {
    "WILDBURROW_TRANSPORTS": "ssh,websocket",
    "WILDBURROW_AUTH": "key,password,token",
    "WILDBURROW_AUTH_TOKEN_HASHES": f"ci:{digest(TOKEN)}",
}


class EchoApp:
    def __init__(self) -> None:
        self.port = 0
        self.requests: list[tuple[str, str | None, str | None]] = []
        self.closed = asyncio.Event()

    async def handle(self, connection: ServerConnection) -> None:
        request = connection.request
        assert request is not None
        self.requests.append((request.path, request.headers.get("Host"), request.headers.get("Origin")))
        await connection.send("hello")
        async for message in connection:
            if message == "bye":
                await connection.close(1000, "done")
                break
            await connection.send(message)
        self.closed.set()


@pytest.fixture
async def echo_app() -> AsyncIterator[EchoApp]:
    app = EchoApp()
    async with serve(app.handle, "127.0.0.1", 0, max_size=None) as server:
        app.port = server.sockets[0].getsockname()[1]
        yield app


@contextlib.asynccontextmanager
async def tunnel(
    running: Running,
    connect: Connect,
    credentials: Credentials,
    transport: str,
    method: str,
    port: int,
    scheme: str = "http",
    connector: Callable | None = None,
) -> AsyncIterator[None]:
    if transport == "ssh":
        client = await connect(running.ssh_port, method, "-R", f"{NAME}:80:127.0.0.1:{port}")
        assert await client.line("ready:") == f"ready: {scheme}://{HOST}"
        yield
        return
    config = client_config(credentials, method, url=f"{scheme}://{DOMAIN}")
    task, out = start_client(running, config, port, [NAME], **({"connector": connector} if connector else {}))
    assert await out.wait_for("ready:") == f"ready: {scheme}://{HOST}"
    yield
    await stop(task)


async def converse(app: EchoApp, uri: str, **kwargs) -> None:
    async with asyncio.timeout(TIMEOUT), ws_connect(uri, origin=ORIGIN, max_size=None, **kwargs) as visitor:
        assert await visitor.recv() == "hello"
        large = bytes(range(256)) * 8192
        await visitor.send(large)
        assert await visitor.recv() == large
        for number in range(50):
            await visitor.send(f"message {number}")
        assert [await visitor.recv() for _ in range(50)] == [f"message {number}" for number in range(50)]
        await visitor.send("bye")
        with pytest.raises(ConnectionClosedOK):
            await visitor.recv()
        assert visitor.close_code == 1000
        assert visitor.close_reason == "done"
        await app.closed.wait()
    assert app.requests == [("/chat?room=1", HOST, ORIGIN)]


@pytest.mark.parametrize(("transport", "method"), TUNNELS)
async def test_websockets_pass_through(
    start_server: StartServer,
    connect: Connect,
    credentials: Credentials,
    echo_app: EchoApp,
    transport: str,
    method: str,
) -> None:
    running = await start_server(**ENV)
    async with tunnel(running, connect, credentials, transport, method, echo_app.port):
        await converse(echo_app, f"ws://{HOST}/chat?room=1", host="127.0.0.1", port=running.http_port)


@pytest.mark.parametrize(("transport", "method"), TUNNELS)
async def test_visitor_closing_reaches_the_local_app(
    start_server: StartServer,
    connect: Connect,
    credentials: Credentials,
    echo_app: EchoApp,
    transport: str,
    method: str,
) -> None:
    running = await start_server(**ENV)
    async with tunnel(running, connect, credentials, transport, method, echo_app.port):
        async with asyncio.timeout(TIMEOUT):
            visitor = await ws_connect(f"ws://{HOST}/", host="127.0.0.1", port=running.http_port)
            assert await visitor.recv() == "hello"
            await visitor.close(1001, "leaving")
            await echo_app.closed.wait()
        assert visitor.close_code == 1001


@pytest.mark.parametrize(("transport", "method"), TUNNELS)
async def test_responses_stream_without_buffering(
    start_server: StartServer, connect: Connect, credentials: Credentials, transport: str, method: str
) -> None:
    first_seen = asyncio.Event()

    async def events(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
        writer.write(b"e\r\ndata: first\n\n\r\n")
        await writer.drain()
        await first_seen.wait()
        writer.write(b"f\r\ndata: second\n\n\r\n0\r\n\r\n")
        await writer.drain()
        writer.close()

    app = await asyncio.start_server(events, "127.0.0.1", 0)
    running = await start_server(**ENV)
    async with app, tunnel(running, connect, credentials, transport, method, app.sockets[0].getsockname()[1]):
        reader, writer = await asyncio.open_connection("127.0.0.1", running.http_port)
        writer.write(f"GET /events HTTP/1.1\r\nHost: {HOST}\r\nAccept: text/event-stream\r\n\r\n".encode())
        async with asyncio.timeout(TIMEOUT):
            received = await reader.readuntil(b"data: first\n\n\r\n")
            first_seen.set()
            received += await reader.read()
        writer.close()
    assert received.startswith(b"HTTP/1.1 200 OK")
    assert received.endswith(b"data: second\n\n\r\n0\r\n\r\n")


@pytest.mark.acme
@pytest.mark.parametrize(("transport", "method"), [("ssh", "key"), ("websocket", "token")])
async def test_secure_websockets_pass_through(
    start_server: StartServer,
    connect: Connect,
    credentials: Credentials,
    echo_app: EchoApp,
    pebble: acme_env.Pebble,
    tls_env: dict[str, str],
    transport: str,
    method: str,
) -> None:
    running = await start_server(**tls_env, **ENV)
    context = ssl.create_default_context(cadata=await asyncio.to_thread(pebble.root))
    connector = functools.partial(ws_connect, host="127.0.0.1", port=running.https_port, ssl=context)
    async with asyncio.timeout(TIMEOUT):
        while not running.server.ctx.certs.ready(DOMAIN):
            await asyncio.sleep(0.1)
    async with tunnel(running, connect, credentials, transport, method, echo_app.port, "https", connector):
        await converse(echo_app, f"wss://{HOST}/chat?room=1", host="127.0.0.1", port=running.https_port, ssl=context)
