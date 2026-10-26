import asyncio
import contextlib
import logging
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.unit.test_certs import NOW, self_signed
from tests.unit.test_edge import LOOPBACK, REQUEST, Root, exchange, running
from tests.unit.test_gate import OTHER, locked
from wildburrow.core.context import ServerContext
from wildburrow.core.indexing import Indexing
from wildburrow.core.locks import Entry
from wildburrow.core.types import Peer
from wildburrow.edge.exchange import (
    BadMessage,
    Body,
    Buffer,
    Exchange,
    Framing,
    closes,
    copy_body,
    request_framing,
    response_framing,
    status_of,
    tagged,
)
from wildburrow.edge.messages import BadRequest, Request, parse_request
from wildburrow.edge.watch import Watch
from wildburrow.store.record import Recorder

HOST = "example.com"
TAG = b"X-Robots-Tag: noindex, nofollow\r\n"

type Script = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class App:
    """A tunnel to a local app run by `script`, over real sockets."""

    def __init__(self, port: int, index: bool | None = None) -> None:
        self.port = port
        self.index = index

    async def open_stream(self, peer: Peer) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.open_connection("127.0.0.1", self.port)


@contextlib.asynccontextmanager
async def app(ctx: ServerContext, script: Script, index: bool | None = None) -> AsyncIterator[list[bytes]]:
    """Serves `script` as the domain's root, handing back everything it was sent, as it reads it."""
    seen: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        recording = Recording(reader, seen)
        with contextlib.suppress(ConnectionError, asyncio.IncompleteReadError):
            await script(recording, writer)  # type: ignore[arg-type]
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    ctx.root = App(server.sockets[0].getsockname()[1], index)
    async with server:
        yield seen
        server.close_clients()


class Recording:
    def __init__(self, reader: asyncio.StreamReader, seen: list[bytes]) -> None:
        self._reader = reader
        self._seen = seen

    async def readuntil(self, separator: bytes) -> bytes:
        found = await self._reader.readuntil(separator)
        self._seen.append(found)
        return found

    async def readexactly(self, size: int) -> bytes:
        found = await self._reader.readexactly(size)
        self._seen.append(found)
        return found

    async def read(self, size: int = -1) -> bytes:
        found = await self._reader.read(size)
        self._seen.append(found)
        return found


def request(path: str = "/", *headers: str, method: str = "GET", host: str = HOST, body: bytes = b"") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", *headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def replying(*responses: bytes, then: Script | None = None) -> Script:
    """An app answering each request head with the next of `responses`, then running `then`."""

    async def script(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        for answer in responses:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(answer)
            await writer.drain()
        if then is not None:
            await then(reader, writer)

    return script


async def visit(ctx: ServerContext, data: bytes) -> bytes:
    async with running(ctx, max_header_bytes=256) as edge:
        return (await exchange("127.0.0.1", edge.port, data))[0]


OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
CLOSING = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbye"


def ours(response: bytes) -> bytes:
    """`response` as the visitor gets it, asking search engines to keep away."""
    head, sep, body = response.partition(b"\r\n\r\n")
    return tagged(head + sep) + body


async def test_every_response_on_a_connection_is_tagged(ctx: ServerContext) -> None:
    async with app(ctx, replying(OK, OK, CLOSING)) as seen:
        reply = await visit(ctx, request("/a") + request("/b") + request("/c"))
    assert reply == ours(OK) + ours(OK) + ours(CLOSING)
    assert [line.split(b" ")[1] for line in seen] == [b"/a", b"/b", b"/c"]


@pytest.mark.parametrize("index", [True, False, None])
async def test_a_tunnel_its_client_lets_be_indexed_is_left_alone(ctx: ServerContext, index: bool | None) -> None:
    ctx.indexing = Indexing.OPT_IN
    async with app(ctx, replying(CLOSING), index):
        reply = await visit(ctx, request())
    assert reply == (CLOSING if index else ours(CLOSING))


async def test_request_bodies_are_relayed_by_length_and_by_chunk(ctx: ServerContext) -> None:
    async def read_both(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        await reader.readexactly(5)
        await reader.readuntil(b"\r\n\r\n")
        while await reader.readuntil(b"\r\n") != b"0\r\n":
            pass
        await reader.readuntil(b"\r\n\r\n")
        writer.write(OK + CLOSING)
        await writer.drain()

    chunked = b"3;x=y\r\nabc\r\n0\r\nTrailer: 1\r\n\r\n"
    data = request("/a", "Content-Length: 5", method="POST", body=b"hello")
    data += request("/b", "Transfer-Encoding: chunked", method="POST", body=chunked)
    async with app(ctx, read_both) as seen:
        reply = await visit(ctx, data)
    assert reply == ours(OK) + ours(CLOSING)
    assert b"".join(seen) == data


@pytest.mark.parametrize(
    "headers",
    [
        ("Transfer-Encoding: chunked", "Content-Length: 3"),
        ("Transfer-Encoding: gzip",),
        ("Content-Length: 3", "Content-Length: 4"),
        ("Content-Length: -3",),
    ],
)
async def test_a_body_that_could_be_read_two_ways_is_refused(ctx: ServerContext, headers: tuple[str, ...]) -> None:
    async with app(ctx, replying()) as seen:
        reply = await visit(ctx, request("/", *headers, method="POST", body=b"abc"))
    assert reply.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert seen == []


async def test_a_later_request_that_could_be_read_two_ways_is_refused_after_the_first_is_answered(
    ctx: ServerContext,
) -> None:
    async with app(ctx, replying(OK)):
        reply = await visit(ctx, request() + request("/", "Content-Length: 1", "Content-Length: 2"))
    assert reply.startswith(ours(OK) + b"HTTP/1.1 400 Bad Request\r\n")


@pytest.mark.parametrize(
    ("later", "status"),
    [
        (request(host="other.example.com"), b"421 Misdirected Request"),
        (b"NOT A REQUEST\r\n\r\n", b"400 Bad Request"),
        (request("/" + "a" * 300), b"431 Request Header Fields Too Large"),
    ],
)
async def test_a_later_request_the_edge_wont_relay_is_answered_in_turn(
    ctx: ServerContext, later: bytes, status: bytes
) -> None:
    async with app(ctx, replying(OK)) as seen:
        reply = await visit(ctx, request() + later)
    assert reply.startswith(ours(OK) + b"HTTP/1.1 " + status + b"\r\n")
    assert len(seen) == 1


@pytest.mark.parametrize(
    ("method", "response"),
    [
        ("HEAD", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
        ("GET", b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n"),
        ("GET", b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n"),
    ],
)
async def test_bodiless_responses_are_followed_by_the_next(ctx: ServerContext, method: str, response: bytes) -> None:
    async with app(ctx, replying(response, CLOSING)):
        reply = await visit(ctx, request(method=method) + request())
    assert reply == ours(response) + ours(CLOSING)


async def test_an_interim_response_goes_ahead_of_the_real_one(ctx: ServerContext) -> None:
    interim = b"HTTP/1.1 100 Continue\r\n\r\n"
    async with app(ctx, replying(interim + CLOSING)):
        reply = await visit(ctx, request())
    assert reply == interim + ours(CLOSING)


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\n\r\nuntil the end",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nuntil the end",
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ],
)
async def test_a_response_that_ends_the_connection_ends_it(ctx: ServerContext, response: bytes) -> None:
    async def hold(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write_eof()
        await reader.read()

    async with app(ctx, replying(response, then=hold)):
        reply = await visit(ctx, request() + request())
    assert reply == ours(response)


async def test_an_http_1_0_response_kept_alive_keeps_the_connection(ctx: ServerContext) -> None:
    kept = b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok"
    async with app(ctx, replying(kept, CLOSING)):
        reply = await visit(ctx, request() + request())
    assert reply == ours(kept) + ours(CLOSING)


async def test_a_request_that_closes_gets_its_answer_and_nothing_after(ctx: ServerContext) -> None:
    async with app(ctx, replying(OK, OK)) as seen:
        reply = await visit(ctx, request("/", "Connection: close") + request())
    assert reply == ours(OK)
    assert len(seen) == 1


async def test_the_app_closing_between_responses_closes_the_visitor(ctx: ServerContext) -> None:
    async with app(ctx, replying(OK)), running(ctx) as edge:
        reader, writer = await asyncio.open_connection("127.0.0.1", edge.port)
        writer.write(request())
        async with asyncio.timeout(2):
            assert await reader.read() == ours(OK)
        writer.close()


async def test_a_websocket_upgrade_hands_the_connection_over(ctx: ServerContext) -> None:
    switched = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"<" + await reader.readexactly(4) + b">")
        await writer.drain()

    async with app(ctx, replying(switched, then=echo)):
        reply = await visit(ctx, request("/ws", "Upgrade: websocket", "Connection: Upgrade") + b"ping")
    assert reply == switched + b"<ping>"


async def test_an_upgrade_turned_down_keeps_the_connection_as_it_was(ctx: ServerContext) -> None:
    async with app(ctx, replying(OK, CLOSING)):
        reply = await visit(ctx, request("/ws", "Upgrade: websocket", "Connection: Upgrade") + request())
    assert reply == ours(OK) + ours(CLOSING)


@pytest.mark.parametrize(
    "response",
    [
        b"NOT HTTP\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\nTrailer",
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
        b"HTTP/1.1 200 OK\r\nContent-Length: nine\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    ],
)
async def test_a_response_that_cant_be_read_ends_the_connection(ctx: ServerContext, response: bytes) -> None:
    async def then(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write_eof()

    async with app(ctx, replying(response, then=then)):
        reply = await visit(ctx, request() + request())
    assert ours(OK) not in reply


async def test_why_an_apps_response_couldnt_be_read_is_logged(
    ctx: ServerContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, "wildburrow")
    async with app(ctx, replying(b"NOT HTTP\r\n\r\n")):
        await visit(ctx, request())
    assert caplog.messages == ["bad response through a tunnel: malformed status line"]
    caplog.clear()
    async with app(ctx, replying(OK)):
        await visit(
            ctx, request() + b"POST / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\nContent-Length: 9\r\n\r\nshort"
        )
    assert caplog.messages == []


async def test_chunked_responses_keep_their_trailers(ctx: ServerContext) -> None:
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\nTrailer: x\r\n\r\n"
    async with app(ctx, replying(chunked, CLOSING)):
        reply = await visit(ctx, request() + request())
    assert reply == ours(chunked) + ours(CLOSING)


def test_framing_reads_the_headers_case_blind() -> None:
    head = b"HTTP/1.1 200 OK\r\nTRANSFER-ENCODING: gzip, Chunked\r\n\r\n"
    assert response_framing("GET", 200, head) == Framing(Body.CHUNKED)
    assert closes(b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive, CLOSE\r\n\r\n")
    assert not closes(b"HTTP/1.1 200 OK\r\n\r\n")
    assert closes(b"GET / HTTP/1.0\r\nHost: a\r\n\r\n")
    assert closes(b"HTTP/1.0 200 OK\r\n\r\n")
    assert not closes(b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n")
    assert not closes(b"HTTP/1.1 200 OK\r\nVia: 1.0 HTTP/1.0 old\r\n\r\n")


async def test_a_head_just_inside_the_limit_is_read() -> None:
    assert await Buffer(Pieces([b"ab\r\n"]), 4).until(b"\r\n") == b"ab\r\n"  # type: ignore[arg-type]


class Pieces:
    """A stream handing out its bytes in the pieces given."""

    def __init__(self, pieces: list[bytes]) -> None:
        self._pieces = list(pieces)

    async def read(self, n: int = -1) -> bytes:
        return self._pieces.pop(0) if self._pieces else b""


class Sink:
    def __init__(self) -> None:
        self.data = b""

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        pass


def split(data: bytes, cuts: list[int]) -> list[bytes]:
    points = sorted({cut % (len(data) + 1) for cut in cuts})
    return [data[start:end] for start, end in zip([0, *points], [*points, len(data)], strict=True) if end > start]


@settings(max_examples=200)
@given(
    chunks=st.lists(st.binary(min_size=1, max_size=40), max_size=5),
    trailers=st.lists(st.from_regex(rb"[A-Za-z]{1,8}: [a-z]{0,8}", fullmatch=True), max_size=2),
    cuts=st.lists(st.integers(min_value=0, max_value=400), max_size=12),
)
def test_chunked_bodies_come_through_whole_however_they_are_split(
    chunks: list[bytes], trailers: list[bytes], cuts: list[int]
) -> None:
    body = b"".join(b"%x\r\n%s\r\n" % (len(chunk), chunk) for chunk in chunks)
    body += b"0\r\n" + b"".join(trailer + b"\r\n" for trailer in trailers) + b"\r\n"
    sink = Sink()
    asyncio.run(copy_body(Buffer(Pieces(split(body + b"next", cuts)), 1024), sink, Framing(Body.CHUNKED)))  # type: ignore[arg-type]
    assert sink.data == body


@settings(max_examples=200)
@given(data=st.binary(max_size=200), cuts=st.lists(st.integers(min_value=0, max_value=200), max_size=12))
def test_lengths_and_heads_come_through_whole_however_they_are_split(data: bytes, cuts: list[int]) -> None:
    async def read() -> tuple[bytes | None, bytes]:
        buffer = Buffer(Pieces(split(b"head\r\n\r\n" + data + b"rest", cuts)), 1024)  # type: ignore[arg-type]
        head = await buffer.until(b"\r\n\r\n")
        sink = Sink()
        await copy_body(buffer, sink, Framing(Body.LENGTH, len(data)))
        return head, sink.data

    assert asyncio.run(read()) == (b"head\r\n\r\n", data)


async def test_a_visitor_done_sending_still_gets_its_answer(ctx: ServerContext) -> None:
    async def answer_after_the_end(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        assert await reader.read() == b""
        writer.write(OK)

    async with app(ctx, answer_after_the_end), running(ctx) as edge:
        reader, writer = await asyncio.open_connection("127.0.0.1", edge.port)
        writer.write(request())
        writer.write_eof()
        async with asyncio.timeout(2):
            assert await reader.read() == ours(OK)
        writer.close()


async def test_an_app_that_closes_without_answering_closes_the_visitor(ctx: ServerContext) -> None:
    async def leave(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")

    async with app(ctx, leave):
        assert await visit(ctx, request()) == b""


async def test_trailers_cut_off_end_the_connection(ctx: ServerContext) -> None:
    async def then(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write_eof()

    cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nTrailer: x\r\n"
    async with app(ctx, replying(cut, then=then)):
        reply = await visit(ctx, request())
    assert reply == ours(cut)


async def test_a_later_head_too_large_to_finish_is_refused(ctx: ServerContext) -> None:
    async with app(ctx, replying(OK)):
        reply = await visit(ctx, request() + b"G" * 300)
    assert reply.startswith(ours(OK) + b"HTTP/1.1 431 ")


def test_framing_is_read_from_the_headers_as_written() -> None:
    assert response_framing("GET", 200, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,chunked\r\n\r\n") == Framing(
        Body.CHUNKED
    )
    assert response_framing("HEAD", 200, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n") == Framing(Body.NONE)
    assert request_framing(parse_request(request())) == Framing(Body.NONE)
    # A colon in a value leaves the name before the first one.
    assert closes(b"HTTP/1.1 200 OK\r\nConnection: close, a:b\r\n\r\n")


def visitor(*pieces: bytes) -> Exchange:
    """An exchange whose visitor sends `pieces`, to read a request body from."""
    return Exchange(
        (Pieces(list(pieces)), Sink()), (Pieces([]), Sink()), limit=64, tag=False, admit=None, refuse=None,
        watch=Watch(Recorder(), None),
    )  # type: ignore[arg-type]  # fmt: skip


async def test_a_body_the_edge_reads_takes_just_its_size() -> None:
    taking = visitor(b"ab", b"cdef")
    assert await taking._take(4) == b"abcd"
    assert await taking._from_visitor.some(10) == b"ef"


async def test_waiting_for_the_end_keeps_reading_up_to_a_heads_worth() -> None:
    buffer = Buffer(Pieces([b"abcd", b"ef", b"gh"]), 4)  # type: ignore[arg-type]
    await buffer.ended()
    assert await buffer.some(10) == b"abcdef"


@pytest.mark.parametrize(
    ("reading", "error", "message"),
    [
        (lambda: Buffer(Pieces([b"abcd"]), 4).until(b"\r\n"), BadMessage, "cut off mid-head"),
        (lambda: Buffer(Pieces([b"abcde"]), 4).until(b"\r\n"), BadMessage, "head too large"),
        (lambda: Buffer(Pieces([b"abc\r\n"]), 4).until(b"\r\n"), BadMessage, "head too large"),
        (lambda: copy_body(Buffer(Pieces([b"ab"]), 64), Sink(), Framing(Body.LENGTH, 4)), BadMessage,
         "cut off mid-body"),
        (lambda: copy_body(Buffer(Pieces([b"zz\r\n"]), 64), Sink(), Framing(Body.CHUNKED)), BadMessage,
         "malformed chunk size"),
        (lambda: copy_body(Buffer(Pieces([b"0\r\nA: b\r\n"]), 64), Sink(), Framing(Body.CHUNKED)), BadMessage,
         "cut off mid-trailers"),
        (lambda: visitor(b"ab")._take(4), BadMessage, "cut off mid-body"),
    ],
)  # fmt: skip
async def test_why_a_message_cant_be_read(reading: Callable[[], Awaitable[object]], error: type, message: str) -> None:
    with pytest.raises(error) as raised:
        await reading()
    assert str(raised.value) == message


@pytest.mark.parametrize(
    ("parsing", "error", "message"),
    [
        (lambda: status_of(b"NOT HTTP\r\n\r\n"), BadMessage, "malformed status line"),
        (lambda: response_framing("GET", 200, b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n"), BadMessage,
         "malformed header line"),
        (lambda: response_framing("GET", 200, b"HTTP/1.1 200 OK\r\nContent-Length: nine\r\n\r\n"), BadMessage,
         "conflicting or malformed Content-Length"),
        (lambda: request_framing(parse_request(request("/", "Content-Length: 1", "Content-Length: 2"))), BadRequest,
         "conflicting or malformed Content-Length"),
        (lambda: request_framing(parse_request(request("/", "Transfer-Encoding: gzip"))), BadRequest,
         "ambiguous request body framing"),
    ],
)  # fmt: skip
def test_why_a_head_cant_be_read(parsing: Callable[[], object], error: type, message: str) -> None:
    with pytest.raises(error) as raised:
        parsing()
    assert str(raised.value) == message


class Seen(Recorder):
    """A record that keeps what the edge tells it about connections, requests and logins."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[object, ...]] = []

    def connection_opened(self, scheme: str, peer: Peer, via_proxy: str | None) -> int:
        self.calls.append(("connection", scheme, via_proxy))
        return 1

    def request(self, connection: int, request: Request, lock: object, entry: Entry | None, status: int | None) -> None:
        self.calls.append(("request", request.target, None if entry is None else entry.label, status))

    def login_attempt(self, lock: object, via: str, label: str | None, entry: object, peer: Peer, *_: object) -> None:
        self.calls.append(("login", via, peer))


@pytest.mark.parametrize(("proxy_from", "via"), [(None, None), (LOOPBACK, "127.0.0.1")])
async def test_a_connection_is_recorded_with_the_proxy_it_came_through(
    ctx: ServerContext, proxy_from: object, via: str | None
) -> None:
    ctx.record = seen = Seen()
    ctx.root = Root()
    data = REQUEST if proxy_from is None else b"PROXY UNKNOWN\r\n" + REQUEST
    async with running(ctx, proxy_from=proxy_from) as edge:
        await exchange("127.0.0.1", edge.port, data)
    assert seen.calls == [("connection", "http", via), ("request", "/", None, 204)]


async def test_a_connection_over_tls_is_recorded_as_https(ctx: ServerContext, tmp_path: Path) -> None:
    key, chain = self_signed(["example.com"], NOW + timedelta(days=1))
    (tmp_path / "key.pem").write_bytes(key)
    (tmp_path / "chain.pem").write_bytes(chain)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(tmp_path / "chain.pem", tmp_path / "key.pem")
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname, client.verify_mode = False, ssl.CERT_NONE
    ctx.record = seen = Seen()
    ctx.root = Root()
    async with running(ctx, tls=server) as edge:
        reader, writer = await asyncio.open_connection("127.0.0.1", edge.port, ssl=client)
        writer.write(REQUEST)
        async with asyncio.timeout(2):
            await reader.read()
        writer.close()
    assert seen.calls[0] == ("connection", "https", None)


class Closed(Seen):
    def connection_closed(self, connection: int, tunnel: int | None, *_: object) -> None:
        self.calls.append(("closed", tunnel))


async def test_a_connection_is_recorded_with_the_tunnel_it_reached(ctx: ServerContext) -> None:
    ctx.record = seen = Closed()
    async with app(ctx, replying(OK)):
        ctx.root.records = [3, 5]  # type: ignore[union-attr]
        await visit(ctx, request("/a"))
        async with asyncio.timeout(2):
            while ("closed", 5) not in seen.calls:
                await asyncio.sleep(0.01)


async def test_later_requests_the_edge_answers_are_recorded(ctx: ServerContext) -> None:
    ctx.record = seen = Seen()
    async with app(ctx, replying(OK)):
        await visit(ctx, request("/a") + request("/b", "Content-Length: 1", "Content-Length: 2"))
    async with app(ctx, replying(OK)):
        await visit(ctx, request("/c") + request("/d", host="other.example.com"))
    assert [call for call in seen.calls if call[0] == "request"] == [
        ("request", "/a", None, 200), ("request", "/b", None, 400),
        ("request", "/c", None, 200), ("request", "/d", None, 421),
    ]  # fmt: skip


async def test_a_response_saying_close_ends_the_connection(ctx: ServerContext) -> None:
    async with app(ctx, replying(CLOSING, OK)):
        reply = await visit(ctx, request() + request())
    assert reply == ours(CLOSING)


def locked_app(ctx: ServerContext, port: int) -> None:
    """A locked tunnel on foo whose app is the one listening on `port`."""
    locked(ctx)
    ctx.registry.resolve(("a", "foo")).open_stream = App(port).open_stream  # type: ignore[union-attr]


AUTH = "X-Wildburrow-Auth: alice:pw"


async def test_every_request_through_a_lock_is_recorded_with_who_and_from_where(ctx: ServerContext) -> None:
    ctx.record = seen = Seen()
    async with app(ctx, replying(OK, CLOSING)):
        locked_app(ctx, ctx.root.port)  # type: ignore[union-attr]
        async with running(ctx) as edge:
            reply, port = await exchange(
                "127.0.0.1", edge.port, request("/a", AUTH, host=OTHER) + request("/b", AUTH, host=OTHER)
            )
    assert reply.endswith(b"bye")
    peer = Peer("127.0.0.1", port)
    assert seen.calls[1:] == [
        ("login", "header", peer), ("login", "header", peer),
        ("request", "/a", "alice", 200), ("request", "/b", "alice", 200),
    ]  # fmt: skip


async def test_an_upgrade_through_a_lock_is_recorded_with_who(ctx: ServerContext) -> None:
    ctx.record = seen = Seen()
    switched = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
    async with app(ctx, replying(switched)):
        locked_app(ctx, ctx.root.port)  # type: ignore[union-attr]
        await visit(ctx, request("/ws", AUTH, "Upgrade: websocket", "Connection: Upgrade", host=OTHER))
    assert seen.calls[-1] == ("request", "/ws", "alice", 101)
