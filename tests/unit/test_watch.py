from typing import Any

import pytest

from wildburrow.edge.watch import Counted, Watch
from wildburrow.store.record import IN, OUT


class Kept:
    """A recorder that remembers what it was asked to write."""

    def __init__(self, traffic: bool = True, traffic_max: int = 0) -> None:
        self.traffic = traffic
        self.traffic_max = traffic_max
        self.chunks: list[tuple[Any, ...]] = []
        self.closed: list[tuple[Any, ...]] = []

    def traffic_chunk(self, *chunk: Any) -> None:
        self.chunks.append(chunk)

    def connection_closed(self, *closed: Any) -> None:
        self.closed.append(closed)


class Clock:
    def __init__(self) -> None:
        self.now = 10.0

    def __call__(self) -> float:
        return self.now


def test_the_bytes_both_ways_are_counted_and_kept_in_order() -> None:
    record, clock = Kept(), Clock()
    watch = Watch(record, 7, clock)  # type: ignore[arg-type]
    watch.crossed(IN, b"GET")
    clock.now += 1.25
    watch.crossed(OUT, b"200 OK")
    watch.crossed(OUT, b"")
    watch.tunnel = 3
    watch.closed()
    assert record.chunks == [(7, 0, IN, 0, b"GET"), (7, 1, OUT, 1250, b"200 OK")]
    assert record.closed == [(7, 3, 3, 6, 1250, False)]


@pytest.mark.parametrize(
    ("most", "kept", "truncated"), [(0, 3, False), (11, 3, False), (10, 2, True), (9, 1, True), (2, 0, True)]
)
def test_traffic_stops_at_the_cap(most: int, kept: int, truncated: bool) -> None:
    record = Kept(traffic_max=most)
    watch = Watch(record, 1, Clock())  # type: ignore[arg-type]
    for data in (b"abcde", b"fghij", b"k"):
        watch.crossed(IN, data)
    assert len(record.chunks) == kept
    assert (watch.bytes_in, watch.truncated) == (11, truncated)


def test_without_traffic_the_connection_is_kept_but_not_its_bytes() -> None:
    record = Kept(traffic=False)
    watch = Watch(record, 1, Clock())  # type: ignore[arg-type]
    watch.crossed(OUT, b"xyz")
    watch.closed()
    assert (record.chunks, record.closed) == ([], [(1, None, 0, 3, 0, False)])


def test_without_a_connection_nothing_is_written() -> None:
    record = Kept()
    watch = Watch(record, None, Clock())  # type: ignore[arg-type]
    watch.crossed(OUT, b"xyz")
    watch.closed()
    assert (record.chunks, record.closed, watch.bytes_out) == ([], [], 3)


class Writer:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def write(self, data: bytes) -> None:
        self.calls.append(data)

    async def drain(self) -> None:
        self.calls.append("drain")

    def write_eof(self) -> None:
        self.calls.append("eof")

    def close(self) -> None:
        self.calls.append("close")


async def test_a_counted_writer_passes_everything_on() -> None:
    record, writer = Kept(), Writer()
    watch = Watch(record, 1, Clock())  # type: ignore[arg-type]
    counted = Counted(writer, OUT, watch)
    counted.write(b"hi")
    await counted.drain()
    counted.write_eof()
    counted.close()
    assert writer.calls == [b"hi", "drain", "eof", "close"]
    assert watch.bytes_out == 2
