"""The server's record in SQLite, in memory or on file: one connection on one worker thread, written in batches."""

import asyncio
import contextlib
import dataclasses
import logging
import os
import sqlite3
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Any

from wildburrow import durations
from wildburrow.config import PREFIX, SHOWN, ConfigError

log = logging.getLogger(__name__)

DATABASE_PREFIX = f"{PREFIX}DATABASE_"
MEMORY = ":memory:"
# 'WBRW': a file without it isn't one of ours.
APPLICATION_ID = 1463964247
VERSION = 1
SCHEMA = (resources.files(__package__) / "schema.sql").read_text()
# Every table whose id the server assigns from a counter, carried on from the largest one already there: each one
# another row points at before the batch carrying it is written.
COUNTED = ("runs", "identities", "commands", "tunnels", "connections", "certificates")
AUTO_VACUUM = "PRAGMA auto_vacuum = INCREMENTAL"
TABLES = "SELECT count(*) FROM sqlite_schema WHERE type = 'table'"
APPLICATION = "PRAGMA application_id"
USER_VERSION = "PRAGMA user_version"
BEGIN, COMMIT, ROLLBACK = "BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"
TIDY = ("PRAGMA incremental_vacuum", "PRAGMA optimize")
CHECKPOINT = "PRAGMA wal_checkpoint(TRUNCATE)"
PRAGMAS = (
    "PRAGMA foreign_keys = ON",
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
    "PRAGMA busy_timeout = 5000",
    "PRAGMA trusted_schema = OFF",
)
# Writes wait for the next batch, unless this many pile up first.
BATCH_SECONDS = 1.0
BATCH_MOST = 1000
PURGE_BATCH = 500
# What memory keeps by default, so a long-running server doesn't grow without end.
MEMORY_KEEP = "1d"
MEMORY_PURGE_EVERY = "1h"
FILE_PURGE_EVERY = "1d"
NEVER = "never"


class DatabaseError(Exception):
    pass


class Record(Enum):
    # Every table, the bytes crossing each tunnel included.
    EVERYTHING = "everything"
    # Every table but the traffic itself.
    ACTIVITY = "activity"
    # Only what's live, each row going as it ends: no history.
    MINIMAL = "minimal"


@dataclasses.dataclass(frozen=True, slots=True)
class DatabaseSettings:
    keep: str = dataclasses.field(default="", metadata={SHOWN: "forever on file, 1d in memory"})
    purge_every: str = dataclasses.field(default="", metadata={SHOWN: "1d on file, 1h in memory, once KEEP is set"})
    record: str = Record.ACTIVITY.value
    traffic_max: int = dataclasses.field(default=0, metadata={SHOWN: "no cap"})


@dataclasses.dataclass(frozen=True, slots=True)
class Storage:
    """Where the record is kept, how much goes in it, and how long it's kept."""

    path: str = MEMORY
    record: Record = Record.ACTIVITY
    # Seconds a finished row is kept; None for forever.
    keep: int | None = None
    purge_every: int | None = None
    # Bytes of traffic kept per connection; 0 for no cap.
    traffic_max: int = 0


def _seconds(var: str, raw: str) -> int | None:
    if raw.strip().lower() == NEVER:
        return None
    if (found := durations.seconds(raw)) is None:
        raise ConfigError(f"{var}: expected a duration {durations.EXAMPLES}, or {NEVER}, got {raw!r}")
    return found


def storage(path: str, settings: DatabaseSettings) -> Storage:
    """What WILDBURROW_DATABASE and the WILDBURROW_DATABASE_* settings ask for, checked."""
    path = path.strip() or MEMORY
    memory = path == MEMORY
    try:
        record = Record(settings.record.strip().lower())
    except ValueError:
        expected = ", ".join(level.value for level in Record)
        raise ConfigError(f"{DATABASE_PREFIX}RECORD: expected one of {expected}, got {settings.record!r}") from None
    if settings.traffic_max < 0:
        raise ConfigError(f"{DATABASE_PREFIX}TRAFFIC_MAX: expected bytes, or 0 for no cap")
    if settings.purge_every and not settings.keep and not memory:
        raise ConfigError(f"{DATABASE_PREFIX}PURGE_EVERY needs {DATABASE_PREFIX}KEEP: there'd be nothing to purge")
    keep = _seconds(f"{DATABASE_PREFIX}KEEP", settings.keep or (MEMORY_KEEP if memory else NEVER))
    every = settings.purge_every or (MEMORY_PURGE_EVERY if memory else FILE_PURGE_EVERY)
    purge_every = None if keep is None else _seconds(f"{DATABASE_PREFIX}PURGE_EVERY", every)
    return Storage(path, record, keep, purge_every, settings.traffic_max)


def _one(connection: sqlite3.Connection, sql: str) -> Any:
    return connection.execute(sql).fetchone()[0]


def connect(path: str) -> sqlite3.Connection:
    """The database at `path`, made if it isn't there and refused if it isn't ours or is newer than this wildburrow."""
    if path != MEMORY:
        Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    # Made and only ever used on the database's own thread.
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        # Only takes on an empty file, so before WAL writes anything.
        connection.execute(AUTO_VACUUM)
        for pragma in PRAGMAS:
            connection.execute(pragma)
        made = _one(connection, TABLES) == 0 and _one(connection, APPLICATION) == 0
    except sqlite3.DatabaseError as exc:
        connection.close()
        raise DatabaseError(f"{path} can't be opened as a database: {exc}") from None
    if made:
        connection.executescript(f"BEGIN; {SCHEMA}; PRAGMA application_id = {APPLICATION_ID}; COMMIT;")
        connection.execute(f"{USER_VERSION} = {VERSION}")
    elif _one(connection, APPLICATION) != APPLICATION_ID:
        connection.close()
        raise DatabaseError(f"{path} isn't a wildburrow database")
    elif (version := _one(connection, USER_VERSION)) > VERSION:
        connection.close()
        raise DatabaseError(f"{path} was written by a newer wildburrow (schema {version}; this one knows {VERSION})")
    return connection


# What purging takes, oldest first: each a table, its key, and when a row of it finished.
PURGED = (
    ("runs", "id", "stopped_at"),
    ("logs", "id", "at"),
    ("auth_attempts", "id", "at"),
    ("sessions", "id", "ended_at"),
    ("locks", "id", "ended_at"),
    ("credentials", "id", "ended_at"),
    ("link_opens", "id", "at"),
    ("login_attempts", "id", "at"),
    ("handoff_codes", "digest", "created_at"),
    ("connections", "id", "at"),
    ("certificates", "id", "finished_at"),
    ("dns_changes", "id", "at"),
    ("tokens", "id", "expires_at"),
)
# Built from the names above, never from anything given.
LARGEST = " UNION ALL ".join(f"SELECT '{name}', max(id) FROM {name}" for name in COUNTED)  # noqa: S608
PURGES = tuple(
    f"DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} WHERE {finished} < ? LIMIT {PURGE_BATCH})"  # noqa: S608
    for table, key, finished in PURGED
)


class Database:
    """A connection the event loop hands work to on one thread, with writes held for the next batch."""

    def __init__(self, storage: Storage, clock: Callable[[], float] = time.time) -> None:
        self.storage = storage
        self._clock = clock
        self._executor = ThreadPoolExecutor(1, thread_name_prefix="wildburrow-database")
        self._connection: sqlite3.Connection | None = None
        self._pending: list[tuple[str, tuple[Any, ...]]] = []
        # The largest id each table holds, read when the database opens.
        self._ids: dict[str, int]
        self._tasks: list[asyncio.Task[None]] = []
        self._flushing: asyncio.Task[None] | None = None

    async def _run[T](self, work: Callable[[sqlite3.Connection], T]) -> T:
        connection = self._connection
        assert connection is not None  # noqa: S101
        return await asyncio.get_running_loop().run_in_executor(self._executor, work, connection)

    async def open(self) -> None:
        loop = asyncio.get_running_loop()
        self._connection = await loop.run_in_executor(self._executor, connect, self.storage.path)
        largest = await self.read(LARGEST)
        self._ids = {name: found or 0 for name, found in largest}
        self._tasks.append(asyncio.create_task(self._batches()))
        if self.storage.purge_every is not None:
            self._tasks.append(asyncio.create_task(self._purges(self.storage.purge_every)))

    def next_id(self, table: str) -> int:
        self._ids[table] += 1
        return self._ids[table]

    def now(self) -> int:
        return int(self._clock())

    def write(self, sql: str, *params: Any) -> None:
        """Queues a write for the next batch, which follows soon once enough are waiting."""
        self._pending.append((sql, params))
        if len(self._pending) >= BATCH_MOST and self._flushing is None:
            self._flushing = asyncio.create_task(self.flush())
            self._flushing.add_done_callback(lambda _: setattr(self, "_flushing", None))

    async def read(self, sql: str, *params: Any) -> list[tuple[Any, ...]]:
        return await self._run(lambda connection: connection.execute(sql, params).fetchall())

    async def flush(self) -> None:
        batch, self._pending = self._pending, []
        if batch:
            await self._run(lambda connection: _apply(connection, batch))

    async def _batches(self) -> None:
        while True:
            await asyncio.sleep(BATCH_SECONDS)
            try:
                await self.flush()
            except sqlite3.Error as exc:
                log.warning("could not write to the database: %s", exc)

    async def _purges(self, every: int) -> None:
        while True:
            try:
                await self.purge()
            except sqlite3.Error as exc:
                log.warning("could not purge the database: %s", exc)
            await asyncio.sleep(every)

    async def purge(self) -> int:
        """Deletes what finished longer ago than the record is kept, a batch at a time; how many rows went."""
        assert self.storage.keep is not None  # noqa: S101
        await self.flush()
        cutoff = self.now() - self.storage.keep
        gone = 0
        for sql in PURGES:
            while count := await self._run(lambda connection, sql=sql: _changed(connection, sql, cutoff)):
                gone += count
        await self._run(_tidy)
        return gone

    async def close(self) -> None:
        for task in self._tasks:
            task.cancel()
        # Waiting for these only orders what the one thread would run in order anyway, before the last flush.
        await asyncio.gather(*self._tasks, return_exceptions=True)  # pragma: no mutate
        if self._flushing is not None:
            # A batch that fails was lost either way; closing goes on.
            with contextlib.suppress(sqlite3.Error):
                await self._flushing
        if self._connection is not None:
            await self.flush()
            await self._run(_finish)
        self._executor.shutdown()


def _apply(connection: sqlite3.Connection, batch: Iterable[tuple[str, tuple[Any, ...]]]) -> None:
    connection.execute(BEGIN)
    try:
        for sql, params in batch:
            connection.execute(sql, params)
    except sqlite3.Error:
        connection.execute(ROLLBACK)
        raise
    connection.execute(COMMIT)


def _changed(connection: sqlite3.Connection, sql: str, cutoff: int) -> int:
    connection.execute(BEGIN)
    count = connection.execute(sql, (cutoff,)).rowcount
    connection.execute(COMMIT)
    return count


def _tidy(connection: sqlite3.Connection) -> None:
    for pragma in (*TIDY, CHECKPOINT):
        connection.execute(pragma)


def _finish(connection: sqlite3.Connection) -> None:
    with contextlib.suppress(sqlite3.Error):
        connection.execute(CHECKPOINT)
    connection.close()
