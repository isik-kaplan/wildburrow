import asyncio
import ipaddress
import struct
from collections.abc import Iterable

from wildburrow.core.types import Peer

V1_PREFIX = b"PROXY "
V1_MAX_LENGTH = 107
V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
V2_HEADER = struct.Struct(">12sBBH")
V2_IPV4 = struct.Struct(">4s4sHH")
V2_IPV6 = struct.Struct(">16s16sHH")
V2_LOCAL, V2_PROXY = 0x20, 0x21
V2_TCP4, V2_TCP6 = 0x11, 0x21

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ProxyHeaderError(Exception):
    pass


def networks(cidrs: Iterable[str]) -> list[Network]:
    return [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]


def trusted(host: str, allowed: list[Network]) -> bool:
    address = ipaddress.ip_address(host)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in network for network in allowed)


async def read_header(reader: asyncio.StreamReader, fallback: Peer) -> Peer:
    start = await reader.readexactly(len(V1_PREFIX))
    if start == V1_PREFIX:
        return _v1(start + await _read_line(reader), fallback)
    rest = await reader.readexactly(V2_HEADER.size - len(start))
    signature, version_command, family, length = V2_HEADER.unpack(start + rest)
    if signature != V2_SIGNATURE:
        raise ProxyHeaderError("missing PROXY protocol header")
    return _v2(version_command, family, await reader.readexactly(length), fallback)


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    line = b""
    while not line.endswith(b"\r\n"):
        if len(line) + len(V1_PREFIX) >= V1_MAX_LENGTH:
            raise ProxyHeaderError("PROXY v1 header too long")
        line += await reader.readexactly(1)
    return line


def _v1(line: bytes, fallback: Peer) -> Peer:
    parts = line.decode("ascii", errors="replace").removesuffix("\r\n").split(" ")
    if len(parts) >= 2 and parts[1] == "UNKNOWN":
        return fallback
    if len(parts) != 6 or parts[1] not in ("TCP4", "TCP6"):
        raise ProxyHeaderError("malformed PROXY v1 header")
    try:
        address = ipaddress.ip_address(parts[2])
        port = int(parts[4])
    except ValueError:
        raise ProxyHeaderError("malformed PROXY v1 address") from None
    if address.version != (4 if parts[1] == "TCP4" else 6) or not 0 <= port <= 65535:
        raise ProxyHeaderError("malformed PROXY v1 address")
    return Peer(str(address), port)


def _v2(version_command: int, family: int, payload: bytes, fallback: Peer) -> Peer:
    if version_command == V2_LOCAL:
        return fallback
    if version_command != V2_PROXY:
        raise ProxyHeaderError("unsupported PROXY v2 command")
    layout = {V2_TCP4: V2_IPV4, V2_TCP6: V2_IPV6}.get(family)
    if layout is None:
        return fallback
    if len(payload) < layout.size:
        raise ProxyHeaderError("truncated PROXY v2 address")
    source, _, source_port, _ = layout.unpack_from(payload)
    return Peer(str(ipaddress.ip_address(source)), source_port)
