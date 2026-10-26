"""One edge connection as the server records it: its requests, the bytes both ways, and with everything kept, them."""

import time
from collections.abc import Callable

from wildburrow.core.locks import Entry, Lock
from wildburrow.core.types import StreamWriter
from wildburrow.edge.messages import Request
from wildburrow.store.record import IN, Recorder


class Watch:
    def __init__(self, record: Recorder, connection: int | None, clock: Callable[[], float] = time.monotonic) -> None:
        self._record = record
        # None when the record keeps no history, which leaves nothing to write.
        self.connection = connection
        self._clock = clock
        self._start = clock()
        self._seq = 0
        self._kept = 0
        # Bytes the app was sent through the tunnel, and bytes the visitor was sent.
        self.bytes_in = self.bytes_out = 0
        self.truncated = False
        self.tunnel: int | None = None
        self.lock: Lock | None = None
        # The first request on the connection, which the edge may answer itself.
        self.request: Request | None = None

    def _ms(self) -> int:
        return int((self._clock() - self._start) * 1000)

    def crossed(self, direction: str, data: bytes) -> None:
        if direction == IN:
            self.bytes_in += len(data)
        else:
            self.bytes_out += len(data)
        # Once cut short, a capture stays cut: a later small chunk would leave a gap that looks whole.
        if self.connection is None or not self._record.traffic or not data or self.truncated:
            return
        most = self._record.traffic_max
        if most and self._kept + len(data) > most:
            self.truncated = True
            return
        self._kept += len(data)
        self._record.traffic_chunk(self.connection, self._seq, direction, self._ms(), data)
        self._seq += 1

    def answered(self, request: Request, entry: Entry | None, status: int | None) -> None:
        if self.connection is not None:
            self._record.request(self.connection, request, self.lock, entry, status)

    def closed(self) -> None:
        if self.connection is not None:
            self._record.connection_closed(
                self.connection, self.tunnel, self.bytes_in, self.bytes_out, self._ms(), self.truncated
            )


class Counted:
    """A writer whose every byte the watch sees go by, in one direction."""

    def __init__(self, writer: StreamWriter, direction: str, watch: Watch) -> None:
        self._writer = writer
        self._direction = direction
        self._watch = watch

    def write(self, data: bytes) -> None:
        self._watch.crossed(self._direction, data)
        self._writer.write(data)

    async def drain(self) -> None:
        await self._writer.drain()

    def write_eof(self) -> None:
        self._writer.write_eof()

    def close(self) -> None:
        self._writer.close()
