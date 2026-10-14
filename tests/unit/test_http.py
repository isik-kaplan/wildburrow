import asyncio

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow.edge.http import HEAD_END, BadRequest, Edge, parse_request
from wildburrow.streams import relay


def head(*lines: str) -> bytes:
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


@pytest.mark.parametrize(
    ("raw", "host"),
    [
        (head("GET / HTTP/1.1", "Host: App.Example.com"), "app.example.com"),
        (head("POST /x?y HTTP/1.0", "Accept: */*", "host:\tapp.example.com:8080 ", "X-A: b"), "app.example.com"),
        (head("OPTIONS /* HTTP/1.1", "Host: a"), "a"),
    ],
)
def test_request_host(raw: bytes, host: str) -> None:
    assert parse_request(raw).host == host


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("GET / HTTP/1.1\r\nHost: \xe9\r\n\r\n".encode("latin-1"), "non-ascii"),
        (head("GET / HTTP/2.0", "Host: a"), "malformed request line"),
        (head("GET /  HTTP/1.1", "Host: a"), "malformed request line"),
        (head("G(T / HTTP/1.1", "Host: a"), "malformed request line"),
        (head("GET http://a/ HTTP/1.1", "Host: a"), "origin-form"),
        (head("CONNECT a:443 HTTP/1.1", "Host: a"), "origin-form"),
        (head("GET / HTTP/1.1", " Host: a"), "malformed header"),
        (head("GET / HTTP/1.1", "Host : a"), "malformed header"),
        (head("GET / HTTP/1.1", "Host: a", "\tfolded"), "malformed header"),
        (head("GET / HTTP/1.1", "NoColon"), "malformed header"),
        (head("GET / HTTP/1.1"), "exactly one Host"),
        (head("GET / HTTP/1.1", "Host: a", "HOST: b"), "exactly one Host"),
        (head("GET / HTTP/1.1", "Host: a:x"), "malformed Host port"),
    ],
)
def test_bad_requests(raw: bytes, reason: str) -> None:
    with pytest.raises(BadRequest, match=reason):
        parse_request(raw)


@given(st.binary(max_size=300))
def test_parse_request_never_crashes(data: bytes) -> None:
    raw = data.split(HEAD_END)[0] + HEAD_END
    try:
        request = parse_request(raw)
    except BadRequest:
        return
    assert request.host == request.host.lower()
    assert ":" not in request.host
    assert request.target.startswith("/")


class Reader:
    def __init__(self, *chunks: bytes | Exception) -> None:
        self.chunks = list(chunks)

    async def read(self, n: int = -1) -> bytes:
        await asyncio.sleep(0)
        item = self.chunks.pop(0) if self.chunks else b""
        if isinstance(item, Exception):
            raise item
        return item


class Writer:
    def __init__(self, eof: bool = True, fail: Exception | None = None) -> None:
        self.data = b""
        self.eof = False
        self.closed = False
        self._can_eof = eof
        self._fail = fail

    def write(self, data: bytes) -> None:
        if self._fail:
            raise self._fail
        self.data += data

    def can_write_eof(self) -> bool:
        return self._can_eof

    def write_eof(self) -> None:
        self.eof = True

    def close(self) -> None:
        self.closed = True

    async def drain(self) -> None:
        pass


async def test_relay_copies_both_ways_and_half_closes() -> None:
    a_writer, b_writer = Writer(), Writer(eof=False)
    await relay((Reader(b"req"), a_writer), (Reader(b"resp", b"onse"), b_writer))
    assert (b_writer.data, a_writer.data) == (b"req", b"response")
    assert a_writer.eof
    assert not b_writer.eof
    assert a_writer.closed
    assert b_writer.closed


async def test_relay_stops_on_connection_errors() -> None:
    a_writer, b_writer = Writer(), Writer(fail=BrokenPipeError())
    await relay((Reader(b"req"), a_writer), (Reader(ConnectionResetError()), b_writer))
    assert a_writer.closed
    assert b_writer.closed


async def test_relay_does_not_swallow_other_errors() -> None:
    with pytest.raises(ExceptionGroup):
        await relay((Reader(ValueError()), Writer()), (Reader(), Writer()))


async def test_client_gone_before_the_response(ctx) -> None:
    edge = Edge(ctx, "127.0.0.1", 0, 1024, 1)
    writer = Writer(fail=ConnectionResetError())
    writer.get_extra_info = lambda key: ("192.0.2.1", 1)
    reader = asyncio.StreamReader()
    reader.feed_data(head("GET / HTTP/1.1", "Host: nowhere.example.com"))
    await edge._handle(reader, writer)
    assert writer.closed


async def test_stop_before_start(ctx) -> None:
    await Edge(ctx, "127.0.0.1", 0, 1024, 1).stop()
