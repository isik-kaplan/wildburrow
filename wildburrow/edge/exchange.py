"""
Every request and response on a visitor's connection, in order: each head read, each body streamed through as it comes,
so a response can be tagged and a request checked without either side's bytes ever being held whole.
"""

import asyncio
import contextlib
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus

from wildburrow.core.locks import Entry
from wildburrow.core.types import StreamReader, StreamWriter
from wildburrow.edge.messages import HEAD_END, NOINDEX, BadRequest, Request, parse_request
from wildburrow.edge.watch import Counted, Watch
from wildburrow.store.record import IN, OUT
from wildburrow.streams import CHUNK

log = logging.getLogger(__name__)
LINE_END = b"\r\n"
# What a header's bytes are read as: every byte is a character, so none can fail to decode.
HEADER_CODING = "latin-1"
STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-9][0-9]{2})(?: .*)?")
CHUNK_SIZE = re.compile(rb"([0-9A-Fa-f]{1,16})(?:;.*)?")
TAG = ": ".join(NOINDEX).encode() + LINE_END
SWITCHING = 101
# Responses that never have a body, whatever their headers say.
BODILESS = frozenset({204, 304})


class BadMessage(Exception):
    pass


class Buffer:
    """Reads from any stream that can `read()`, by line and by count, keeping what it read past."""

    def __init__(self, reader: StreamReader, limit: int) -> None:
        self._reader = reader
        self._limit = limit
        self._data = b""

    async def _more(self) -> bool:
        chunk = await self._reader.read(CHUNK)
        self._data += chunk
        return bool(chunk)

    async def until(self, end: bytes) -> bytes | None:
        """Everything up to and including `end`; None when the stream ends cleanly before any of it."""
        while (at := self._data.find(end)) < 0:
            if len(self._data) > self._limit:
                raise BadMessage("head too large")
            if not await self._more():
                if self._data:
                    raise BadMessage("cut off mid-head")
                return None
        found, self._data = self._data[: at + len(end)], self._data[at + len(end) :]
        if len(found) > self._limit:
            raise BadMessage("head too large")
        return found

    @property
    def holding(self) -> bool:
        """Whether anything read is still waiting to be taken."""
        return bool(self._data)

    async def ended(self) -> None:
        """Returns once the stream ends, keeping anything read meanwhile; or once that's more than a head's worth."""
        while len(self._data) <= self._limit and await self._more():
            pass

    async def some(self, most: int) -> bytes:
        """Up to `most` bytes, waiting for at least one; empty at the end of the stream."""
        if not self._data and not await self._more():
            return b""
        found, self._data = self._data[:most], self._data[most:]
        return found

    async def exactly(self, size: int, writer: StreamWriter) -> None:
        """Copies `size` bytes to `writer`, as they come."""
        while size:
            chunk = await self.some(min(size, CHUNK))
            if not chunk:
                raise BadMessage("cut off mid-body")
            writer.write(chunk)
            await writer.drain()
            size -= len(chunk)

    async def rest(self, writer: StreamWriter) -> None:
        """Copies everything until the stream ends."""
        while chunk := await self.some(CHUNK):
            writer.write(chunk)
            await writer.drain()


class Body(Enum):
    NONE = "none"
    LENGTH = "length"
    CHUNKED = "chunked"
    UNTIL_CLOSE = "until-close"


@dataclass(frozen=True, slots=True)
class Framing:
    body: Body
    length: int = 0


def _headers(head: bytes) -> list[tuple[str, str]]:
    lines = head.removesuffix(HEAD_END).split(LINE_END)[1:]
    found = []
    for line in lines:
        name, sep, value = line.decode(HEADER_CODING).partition(":")
        if not sep:
            raise BadMessage("malformed header line")
        found.append((name.strip().lower(), value.strip()))
    return found


def _length(values: list[str]) -> int:
    if len(set(values)) != 1 or not values[0].isdigit():
        raise BadMessage("conflicting or malformed Content-Length")
    return int(values[0])


def _codings(headers: list[tuple[str, str]]) -> list[str]:
    return [
        coding.strip().lower() for name, value in headers if name == "transfer-encoding" for coding in value.split(",")
    ]


def request_framing(request: Request) -> Framing:
    """How a request's body is framed; one that could be read two ways is refused, so nothing can be smuggled past."""
    headers = [(name.lower(), value) for name, value in request.headers]
    codings = _codings(headers)
    lengths = [value for name, value in headers if name == "content-length"]
    if codings:
        if lengths or codings[-1] != "chunked":
            raise BadRequest("ambiguous request body framing")
        return Framing(Body.CHUNKED)
    if lengths:
        try:
            return Framing(Body.LENGTH, _length(lengths))
        except BadMessage as exc:
            raise BadRequest(str(exc)) from None
    return Framing(Body.NONE)


def status_of(head: bytes) -> int:
    match = STATUS_LINE.fullmatch(head.partition(LINE_END)[0])
    if match is None:
        raise BadMessage("malformed status line")
    return int(match[1])


def response_framing(method: str, status: int, head: bytes) -> Framing:
    if method == "HEAD" or status in BODILESS or status < 200:
        return Framing(Body.NONE)
    headers = _headers(head)
    codings = _codings(headers)
    if codings:
        return Framing(Body.CHUNKED) if codings[-1] == "chunked" else Framing(Body.UNTIL_CLOSE)
    lengths = [value for name, value in headers if name == "content-length"]
    return Framing(Body.LENGTH, _length(lengths)) if lengths else Framing(Body.UNTIL_CLOSE)


def closes(head: bytes) -> bool:
    """Whether the message whose head this is ends its connection, as HTTP/1.0 does unless kept alive."""
    tokens = {
        token.strip().lower() for name, value in _headers(head) if name == "connection" for token in value.split(",")
    }
    old = b" HTTP/1.0" in head.partition(LINE_END)[0] or head.startswith(b"HTTP/1.0 ")
    return "close" in tokens or (old and "keep-alive" not in tokens)


def tagged(head: bytes) -> bytes:
    """`head` asking search engines not to index the page or follow its links."""
    return head[: -len(LINE_END)] + TAG + LINE_END


async def copy_body(source: Buffer, writer: StreamWriter, framing: Framing) -> None:
    match framing.body:
        case Body.LENGTH:
            await source.exactly(framing.length, writer)
        case Body.CHUNKED:
            await _copy_chunks(source, writer)
        case Body.UNTIL_CLOSE:
            await source.rest(writer)


async def _copy_chunks(source: Buffer, writer: StreamWriter) -> None:
    while True:
        line = await source.until(LINE_END)
        if line is None or (match := CHUNK_SIZE.fullmatch(line.removesuffix(LINE_END))) is None:
            raise BadMessage("malformed chunk size")
        writer.write(line)
        size = int(match[1], 16)
        if not size:
            break
        await source.exactly(size + len(LINE_END), writer)
    # Trailers, ending at an empty line.
    while (line := await source.until(LINE_END)) != LINE_END:
        if line is None:
            raise BadMessage("cut off mid-trailers")
        writer.write(line)
    writer.write(LINE_END)
    await writer.drain()


@dataclass(frozen=True, slots=True)
class Forward:
    """A later request let through, with the head to send the tunnel, and who it's from on a locked tunnel."""

    head: bytes
    entry: Entry | None = None


@dataclass(frozen=True, slots=True)
class Answer:
    """The edge's own response to a later request, after which the connection ends."""

    response: bytes


# Reads `size` bytes of the request body, for the edge to answer a request itself.
type ReadBody = Callable[[int], Awaitable[bytes]]
# Admits a later request, given as parsed and as it came.
type Admit = Callable[[Request, bytes, ReadBody], Awaitable[Forward | Answer]]


@dataclass(frozen=True, slots=True)
class _Expect:
    """What the next response written to the visitor is: the tunnel's to `request`, or the edge's own."""

    request: Request | None = None
    entry: Entry | None = None
    upgrade: asyncio.Future[bool] | None = None
    own: bytes | None = None


class _Done(Exception):
    """Nothing more can be written to the visitor."""


class Exchange:
    def __init__(
        self,
        visitor: tuple[StreamReader, StreamWriter],
        upstream: tuple[StreamReader, StreamWriter],
        *,
        limit: int,
        tag: bool,
        admit: Admit,
        refuse: Callable[[HTTPStatus], bytes],
        watch: Watch,
    ) -> None:
        self._from_visitor, self._to_visitor = Buffer(visitor[0], limit), Counted(visitor[1], OUT, watch)
        self._from_tunnel, self._to_tunnel = Buffer(upstream[0], limit), Counted(upstream[1], IN, watch)
        self._watch = watch
        self._tag = tag
        self._admit = admit
        self._refuse = refuse
        self._expected: asyncio.Queue[_Expect | None] = asyncio.Queue()

    async def run(self, head: bytes, request: Request, entry: Entry | None) -> None:
        """Relays `request`, whose `head` was already read and checked, and every request after it."""
        try:
            async with asyncio.TaskGroup() as group:
                group.create_task(self._requests_until_cut_off(head, request, entry))
                group.create_task(self._responses())
        except* BadMessage as bad:
            # The visitor's half stops at what it can't read itself, so this is the app's answer.
            log.info("bad response through a tunnel: %s", bad.exceptions[0])
        except* _Done, OSError:
            pass
        finally:
            self._to_visitor.close()
            self._to_tunnel.close()

    async def _take(self, size: int) -> bytes:
        found = b""
        while len(found) < size:
            chunk = await self._from_visitor.some(size - len(found))
            if not chunk:
                raise BadMessage("cut off mid-body")
            found += chunk
        return found

    async def _requests_until_cut_off(self, head: bytes, request: Request, entry: Entry | None) -> None:
        try:
            await self._requests(head, request, entry)
        except BadMessage:
            # The visitor stopped mid-request; what it asked before that is still answered.
            self._expected.put_nowait(None)

    async def _requests(self, head: bytes, request: Request, entry: Entry | None) -> None:
        while True:
            try:
                framing = request_framing(request)
            except BadRequest:
                self._expected.put_nowait(_Expect(request, own=self._refuse(HTTPStatus.BAD_REQUEST)))
                return
            upgrade = asyncio.get_running_loop().create_future() if request.header("upgrade") is not None else None
            self._expected.put_nowait(_Expect(request, entry, upgrade))
            self._to_tunnel.write(head)
            await copy_body(self._from_visitor, self._to_tunnel, framing)
            await self._to_tunnel.drain()
            if upgrade is not None and await upgrade:
                await self._from_visitor.rest(self._to_tunnel)
                return
            if closes(head):
                self._expected.put_nowait(None)
                return
            try:
                head = await self._from_visitor.until(HEAD_END)
            except BadMessage:
                self._expected.put_nowait(_Expect(own=self._refuse(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE)))
                return
            if head is None:
                self._expected.put_nowait(None)
                self._to_tunnel.write_eof()
                return
            try:
                request = parse_request(head)
            except BadRequest:
                self._expected.put_nowait(_Expect(own=self._refuse(HTTPStatus.BAD_REQUEST)))
                return
            admitted = await self._admit(request, head, self._take)
            if isinstance(admitted, Answer):
                self._expected.put_nowait(_Expect(request, own=admitted.response))
                return
            head, entry = admitted.head, admitted.entry

    async def _next(self) -> _Expect | None:
        """The next response to write, unless the tunnel's side closes first, which leaves nothing to relay to."""
        getting = asyncio.ensure_future(self._expected.get())
        ending = asyncio.ensure_future(self._from_tunnel.ended())
        await asyncio.wait({getting, ending}, return_when=asyncio.FIRST_COMPLETED)
        if not getting.done() and not self._from_tunnel.holding:
            getting.cancel()
            raise _Done
        ending.cancel()
        # The tunnel can't be read again until this read has let go of it.
        with contextlib.suppress(asyncio.CancelledError):
            await ending
        # Ended with answers still to hand over, which go to the requests they answer.
        return await getting

    async def _responses(self) -> None:
        while (expected := await self._next()) is not None:
            if expected.own is not None:
                if expected.request is not None:
                    self._watch.answered(expected.request, None, status_of(expected.own))
                self._to_visitor.write(expected.own)
                await self._to_visitor.drain()
                raise _Done
            await self._response(expected)
        raise _Done

    async def _response(self, expected: _Expect) -> None:
        while True:
            head = await self._from_tunnel.until(HEAD_END)
            if head is None:
                raise _Done
            status = status_of(head)
            if status == SWITCHING and expected.upgrade is not None:
                self._watch.answered(expected.request, expected.entry, status)
                self._to_visitor.write(head)
                expected.upgrade.set_result(True)
                await self._from_tunnel.rest(self._to_visitor)
                raise _Done
            if status >= 200:
                break
            # 100 Continue and the like, ahead of the response itself.
            self._to_visitor.write(head)
        if expected.upgrade is not None:
            # Read only for whether it's true, so None would turn the upgrade down the same.
            expected.upgrade.set_result(False)  # pragma: no mutate
        self._watch.answered(expected.request, expected.entry, status)
        framing = response_framing(expected.request.method, status, head)
        self._to_visitor.write(tagged(head) if self._tag else head)
        await copy_body(self._from_tunnel, self._to_visitor, framing)
        await self._to_visitor.drain()
        if framing.body is Body.UNTIL_CLOSE or closes(head):
            raise _Done
