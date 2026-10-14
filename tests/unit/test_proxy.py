import asyncio
import ipaddress
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow.core.types import Peer
from wildburrow.edge import proxy

FALLBACK = Peer("10.0.0.2", 4000)
V6_PAYLOAD = proxy.V2_IPV6.pack(ipaddress.ip_address("2001:db8::1").packed, bytes(16), 7, 8)


def v2(command: int, family: int, payload: bytes) -> bytes:
    return proxy.V2_SIGNATURE + struct.pack(">BBH", command, family, len(payload)) + payload


async def parse(data: bytes) -> Peer:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return await proxy.read_header(reader, FALLBACK)


@pytest.mark.parametrize(
    ("data", "peer"),
    [
        (b"PROXY TCP4 203.0.113.9 10.0.0.1 51000 443\r\n", Peer("203.0.113.9", 51000)),
        (b"PROXY TCP6 2001:db8::1 2001:db8::2 51000 443\r\n", Peer("2001:db8::1", 51000)),
        (b"PROXY UNKNOWN\r\n", FALLBACK),
        (b"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n", FALLBACK),
        (v2(proxy.V2_PROXY, proxy.V2_TCP4, proxy.V2_IPV4.pack(bytes([203, 0, 113, 9]), bytes(4), 51000, 443)),
         Peer("203.0.113.9", 51000)),
        (v2(proxy.V2_PROXY, proxy.V2_TCP6, V6_PAYLOAD + b"tlv"), Peer("2001:db8::1", 7)),
        (v2(proxy.V2_LOCAL, 0, b""), FALLBACK),
        (v2(proxy.V2_PROXY, 0x31, b"unix sockets"), FALLBACK),
    ],
)  # fmt: skip
async def test_headers(data: bytes, peer: Peer) -> None:
    assert await parse(data + b"GET / HTTP/1.1\r\n") == peer


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"PROXY TCP4 203.0.113.9 10.0.0.1 51000\r\n", "malformed PROXY v1 header"),
        (b"PROXY UDP4 203.0.113.9 10.0.0.1 1 2\r\n", "malformed PROXY v1 header"),
        (b"PROXY TCP4 2001:db8::1 10.0.0.1 1 2\r\n", "malformed PROXY v1 address"),
        (b"PROXY TCP4 nope 10.0.0.1 1 2\r\n", "malformed PROXY v1 address"),
        (b"PROXY TCP4 1.2.3.4 10.0.0.1 99999 2\r\n", "malformed PROXY v1 address"),
        (b"PROXY TCP4 1.2.3.4 10.0.0.1 x 2\r\n", "malformed PROXY v1 address"),
        (b"PROXY " + b"A" * 200 + b"\r\n", "too long"),
        (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "missing PROXY protocol header"),
        (v2(0x22, proxy.V2_TCP4, bytes(12)), "unsupported PROXY v2 command"),
        (v2(proxy.V2_PROXY, proxy.V2_TCP4, bytes(4)), "truncated PROXY v2 address"),
    ],
)
async def test_bad_headers(data: bytes, reason: str) -> None:
    with pytest.raises(proxy.ProxyHeaderError, match=reason):
        await parse(data)


@given(st.binary(max_size=120))
async def test_random_input_never_crashes(data: bytes) -> None:
    try:
        peer = await parse(data)
    except proxy.ProxyHeaderError, asyncio.IncompleteReadError:
        return
    ipaddress.ip_address(peer.host)
    assert 0 <= peer.port <= 65535


def test_trusted_networks() -> None:
    allowed = proxy.networks(["10.0.0.0/8", "fd00::/8"])
    assert proxy.trusted("10.1.2.3", allowed)
    assert proxy.trusted("::ffff:10.1.2.3", allowed)
    assert proxy.trusted("fd00::1", allowed)
    assert not proxy.trusted("203.0.113.9", allowed)
    assert not proxy.trusted("::1", allowed)
