import asyncio
import contextlib
import dataclasses
import logging
import re
import sqlite3
import stat
import threading
import zlib
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

from tests.unit.test_registry import FakeTunnel
from wildburrow.config import ConfigError
from wildburrow.core.locks import LINK, PASSWORD, Lock, Locking
from wildburrow.core.sessions import Session
from wildburrow.core.types import Identity, Peer
from wildburrow.edge.messages import parse_request
from wildburrow.locks import DEFAULTS
from wildburrow.store import database, record
from wildburrow.store.database import (
    APPLICATION_ID,
    MEMORY,
    VERSION,
    Database,
    DatabaseError,
    DatabaseSettings,
    Record,
    Storage,
    connect,
    storage,
)
from wildburrow.store.record import IN, OUT, Handler, Recorder, credential_id, packed

NOW = 1_800_000_000
DAY = 86400
ALICE = Identity("alice", "token", "alice-token", names=("alice",), expires=NOW + DAY, token="t1")
LAPTOP = Identity("laptop", "key", "SHA256:abc")
PEER = Peer("203.0.113.4", 50000)


class Clock:
    def __init__(self) -> None:
        self.now = float(NOW)

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(
    ("path", "settings", "expected"),
    [
        ("", DatabaseSettings(), Storage(MEMORY, Record.ACTIVITY, DAY, 3600)),
        (":memory:", DatabaseSettings(keep="never"), Storage(MEMORY, Record.ACTIVITY, None, None)),
        (" /x.db ", DatabaseSettings(), Storage("/x.db", Record.ACTIVITY, None, None)),
        ("/x.db", DatabaseSettings(keep="7d"), Storage("/x.db", Record.ACTIVITY, 7 * DAY, DAY)),
        ("/x.db", DatabaseSettings(keep="7d", purge_every="1h", record=" Everything ", traffic_max=10),
         Storage("/x.db", Record.EVERYTHING, 7 * DAY, 3600, 10)),
        ("", DatabaseSettings(purge_every="5m", record="minimal"), Storage(MEMORY, Record.MINIMAL, DAY, 300)),
        ("", DatabaseSettings(keep="NEVER", purge_every="5m"), Storage(MEMORY, Record.ACTIVITY, None, None)),
    ],
)  # fmt: skip
def test_storage_is_read_from_the_settings(path: str, settings: DatabaseSettings, expected: Storage) -> None:
    assert storage(path, settings) == expected


@pytest.mark.parametrize(
    ("path", "settings", "message"),
    [
        ("", DatabaseSettings(record="some"),
         "WILDBURROW_DATABASE_RECORD: expected one of everything, activity, minimal, got 'some'"),
        ("", DatabaseSettings(traffic_max=-1), "WILDBURROW_DATABASE_TRAFFIC_MAX: expected bytes, or 0 for no cap"),
        ("/x.db", DatabaseSettings(purge_every="1h"),
         "WILDBURROW_DATABASE_PURGE_EVERY needs WILDBURROW_DATABASE_KEEP: there'd be nothing to purge"),
        ("", DatabaseSettings(keep="a while"),
         "WILDBURROW_DATABASE_KEEP: expected a duration like 30m, 12h or 7d, or never, got 'a while'"),
        ("", DatabaseSettings(purge_every="often"),
         "WILDBURROW_DATABASE_PURGE_EVERY: expected a duration like 30m, 12h or 7d, or never, got 'often'"),
    ],
)  # fmt: skip
def test_storage_settings_that_cant_be_are_refused(path: str, settings: DatabaseSettings, message: str) -> None:
    with pytest.raises(ConfigError) as error:
        storage(path, settings)
    assert str(error.value) == message


def peek(path: Path, sql: str) -> list[tuple[Any, ...]]:
    """What `sql` finds in the file at `path`, read and closed again."""
    with contextlib.closing(sqlite3.connect(path)) as connection:
        return connection.execute(sql).fetchall()


def pragma(connection: sqlite3.Connection, name: str) -> Any:
    return connection.execute(f"PRAGMA {name}").fetchone()[0]


def test_a_new_file_is_made_private_and_ours(tmp_path: Path) -> None:
    path = tmp_path / "deep" / "er" / "wildburrow.db"
    connection = connect(str(path))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert (pragma(connection, "application_id"), pragma(connection, "user_version")) == (APPLICATION_ID, VERSION)
    assert (pragma(connection, "journal_mode"), pragma(connection, "auto_vacuum")) == ("wal", 2)
    assert (pragma(connection, "foreign_keys"), pragma(connection, "trusted_schema")) == (1, 0)
    # Batches begin and end their own transactions.
    assert connection.isolation_level is None
    connection.close()
    again = connect(str(path))
    assert pragma(again, "user_version") == VERSION
    again.close()


def test_an_empty_file_counts_as_new(tmp_path: Path) -> None:
    path = tmp_path / "empty.db"
    path.touch()
    connect(str(path)).close()
    assert peek(path, "PRAGMA application_id")[0][0] == APPLICATION_ID


def test_memory_is_made_each_time() -> None:
    with contextlib.closing(connect(MEMORY)) as connection:
        assert pragma(connection, "journal_mode") == "memory"
        assert pragma(connection, "user_version") == VERSION


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("CREATE TABLE theirs (x)", "isn't a wildburrow database"),
        ("PRAGMA application_id = 1", "isn't a wildburrow database"),
        (f"PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = {VERSION + 1}",
         f"was written by a newer wildburrow (schema {VERSION + 1}; this one knows {VERSION})"),
    ],
)  # fmt: skip
def test_a_file_that_isnt_ours_or_is_newer_is_refused(tmp_path: Path, setup: str, message: str) -> None:
    path = tmp_path / "other.db"
    with contextlib.closing(sqlite3.connect(path)) as other:
        other.executescript(setup)
    with pytest.raises(DatabaseError, match=f"^{re.escape(f'{path} {message}')}$"):
        connect(str(path))


def test_a_file_that_isnt_a_database_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("not a database, just long enough to look like a header to sqlite\n" * 4)
    with pytest.raises(DatabaseError, match=f"^{path} can't be opened as a database: "):
        connect(str(path))


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    found = Database(Storage(str(tmp_path / "w.db"), Record.EVERYTHING, DAY, None), Clock())
    await found.open()
    yield found
    await found.close()


def run_row(db: Database) -> int:
    run = db.next_id("runs")
    db.write(
        "INSERT INTO runs (id, version, hostname, domain, settings, started_at) VALUES (?, ?, ?, ?, ?, ?)",
        run, "0", "host", "example.com", "{}", NOW,
    )  # fmt: skip
    return run


async def test_writes_wait_for_their_batch(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    run_row(db)
    assert await db.read("SELECT count(*) FROM runs") == [(0,)]
    await db.flush()
    assert await db.read("SELECT id FROM runs") == [(1,)]


async def test_enough_writes_go_without_waiting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database, "BATCH_MOST", 3)
    monkeypatch.setattr(database, "BATCH_SECONDS", 60)
    db = Database(Storage(str(tmp_path / "w.db")))
    await db.open()
    for written in (3, 6):
        for _ in range(2):
            run_row(db)
        await asyncio.sleep(0.05)
        assert await db.read("SELECT count(*) FROM runs") == [(written - 3,)]
        run_row(db)
        async with asyncio.timeout(2):
            while (await db.read("SELECT count(*) FROM runs")) != [(written,)]:
                await asyncio.sleep(0.01)
    await db.close()


async def test_a_read_takes_its_parameters(db: Database) -> None:
    assert await db.read("SELECT ? + ?", 1, 2) == [(3,)]


async def test_the_database_has_a_thread_of_its_own(db: Database) -> None:
    assert (await db._run(lambda connection: threading.current_thread().name)).startswith("wildburrow-database")


async def test_closing_lets_an_early_batch_fail_quietly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database, "BATCH_MOST", 1)
    db = Database(Storage(str(tmp_path / "w.db")))
    await db.open()
    db.write("INSERT INTO nowhere VALUES (1)")
    await db.close()


def test_a_checkpoint_that_fails_still_closes() -> None:
    class Busy:
        closed = False

        def execute(self, sql: str) -> None:
            raise sqlite3.OperationalError("database is locked")

        def close(self) -> None:
            self.closed = True

    busy = Busy()
    database._finish(busy)  # type: ignore[arg-type]
    assert busy.closed


async def test_batches_go_out_every_so_often(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database, "BATCH_SECONDS", 0.01)
    db = Database(Storage(str(tmp_path / "w.db")))
    await db.open()
    run_row(db)
    async with asyncio.timeout(2):
        while (await db.read("SELECT count(*) FROM runs")) != [(1,)]:
            await asyncio.sleep(0.01)
    await db.close()


async def test_a_batch_that_fails_is_logged_and_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(database, "BATCH_SECONDS", 0.01)
    db = Database(Storage(str(tmp_path / "w.db")))
    await db.open()
    run_row(db)
    db.write("INSERT INTO logs (id, run_id, at, level, logger, message) VALUES (1, 99, 0, 'INFO', 'x', 'y')")
    async with asyncio.timeout(2):
        while not caplog.records:
            await asyncio.sleep(0.01)
    assert caplog.records[0].getMessage() == "could not write to the database: FOREIGN KEY constraint failed"
    assert await db.read("SELECT count(*) FROM runs") == [(0,)]
    run_row(db)
    await db.close()
    caplog.clear()


async def test_ids_carry_on_from_the_file(tmp_path: Path) -> None:
    path = str(tmp_path / "w.db")
    first = Database(Storage(path))
    await first.open()
    assert [run_row(first) for _ in range(2)] == [1, 2]
    await first.close()
    second = Database(Storage(path))
    await second.open()
    assert run_row(second) == 3
    await second.close()


async def test_purging_takes_only_what_finished_long_enough_ago(tmp_path: Path) -> None:
    clock = Clock()
    db = Database(Storage(str(tmp_path / "w.db"), Record.ACTIVITY, DAY, None), clock)
    await db.open()
    old, live = run_row(db), run_row(db)
    db.write("UPDATE runs SET started_at = ?, stopped_at = ? WHERE id = ?", NOW - 2 * DAY, NOW - DAY - 1, old)
    for at in (NOW - DAY - 1, NOW - DAY, NOW):
        db.write(
            "INSERT INTO logs (run_id, at, level, logger, message) VALUES (?, ?, 'INFO', 'x', 'y')", live, at,
        )  # fmt: skip
    assert await db.purge() == 2
    assert await db.read("SELECT id FROM runs") == [(live,)]
    assert await db.read("SELECT at FROM logs ORDER BY at") == [(NOW - DAY,), (NOW,)]
    await db.close()


async def test_purging_goes_a_batch_at_a_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database, "PURGES", tuple(sql.replace("LIMIT 500", "LIMIT 2") for sql in database.PURGES))
    db = Database(Storage(str(tmp_path / "w.db"), Record.ACTIVITY, DAY, None), Clock())
    await db.open()
    run = run_row(db)
    for _ in range(5):
        db.write(
            "INSERT INTO logs (run_id, at, level, logger, message) VALUES (?, 0, 'INFO', 'x', 'y')", run,
        )  # fmt: skip
    assert await db.purge() == 5
    await db.close()


async def test_a_purge_runs_at_start_and_then_every_so_often(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    runs: list[float] = []
    failing = [True]

    async def purge(self: Database) -> int:
        runs.append(asyncio.get_running_loop().time())
        if failing.pop() if failing else False:
            raise sqlite3.OperationalError("disk I/O error")
        return 0

    monkeypatch.setattr(Database, "purge", purge)
    db = Database(Storage(str(tmp_path / "w.db"), Record.ACTIVITY, DAY, 0))
    await db.open()
    async with asyncio.timeout(2):
        while len(runs) < 3:
            await asyncio.sleep(0.01)
    await db.close()
    assert [record.getMessage() for record in caplog.records] == ["could not purge the database: disk I/O error"]
    caplog.clear()


async def test_without_a_keep_nothing_is_purged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[bool] = []

    async def purge(self: Database) -> int:
        called.append(True)
        return 0

    monkeypatch.setattr(Database, "purge", purge)
    db = Database(Storage(str(tmp_path / "w.db")))
    await db.open()
    await asyncio.sleep(0.05)
    await db.close()
    assert called == []


async def test_closing_writes_what_waits_and_closes_the_file(tmp_path: Path) -> None:
    path = tmp_path / "w.db"
    db = Database(Storage(str(path)))
    await db.open()
    run_row(db)
    await db.close()
    assert peek(path, "SELECT count(*) FROM runs")[0] == (1,)
    wal = Path(f"{path}-wal")
    assert not wal.exists() or wal.stat().st_size == 0  # noqa: ASYNC240


async def test_closing_waits_for_a_batch_already_going(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database, "BATCH_MOST", 1)
    path = tmp_path / "w.db"
    db = Database(Storage(str(path)))
    await db.open()
    run_row(db)
    await db.close()
    assert peek(path, "SELECT count(*) FROM runs")[0] == (1,)


async def test_closing_a_database_never_opened_is_quiet() -> None:
    await Database(Storage()).close()


async def lost(recorder: Recorder, *writes: Callable[[], object]) -> None:
    """`writes` in a batch that fails."""
    assert recorder._database is not None
    for write in writes:
        write()
    recorder._database.write("INSERT INTO nowhere VALUES (1)")
    with pytest.raises(sqlite3.Error):
        await recorder._database.flush()


async def test_rows_after_a_lost_batch_still_point_at_their_own(recorder: Recorder) -> None:
    one = session(LAPTOP)
    recorder.session_opened(one, False, {})
    await rows(recorder, "SELECT 1")
    # Ids handed out for rows that never land are skipped, where sqlite would hand them out again.
    await lost(
        recorder,
        lambda: recorder.tunnel_opened(one, None, False, {"lost": "http://lost.example.com"}),
        lambda: recorder.command(one, "kick", {}),
        lambda: recorder.connection_opened("http", PEER, None),
        lambda: recorder.certificate_requested("lost.example.com"),
        lambda: recorder.identity(Identity("ghost", "key", "SHA256:ghost")),
    )
    other = session(Identity("other", "key", "SHA256:other"), 2)
    recorder.session_opened(other, False, {})
    tunnel = recorder.tunnel_opened(one, None, False, {"foo": "http://foo.example.com"})
    await rows(recorder, "SELECT 1")
    await lost(recorder, lambda: recorder.tunnel_opened(one, None, False, {}))
    recorder.tunnel_rejected(one, ["bar"], "bar: taken")
    recorder.session_closed(one, "ended by laptop", recorder.command(one, "kick", {}))
    named = "SELECT tunnel_id, name FROM tunnel_names JOIN tunnels ON tunnels.id = tunnel_id ORDER BY tunnel_id"
    assert await rows(recorder, named) == [(tunnel, "foo"), (tunnel + 2, "bar")]
    connection = recorder.connection_opened("http", PEER, None)
    certificate = recorder.certificate_requested("foo.example.com")
    assert certificate is not None
    recorder.certificate_finished(certificate, None)
    assert await rows(recorder, "SELECT id FROM connections") == [(connection,)]
    assert await rows(recorder, "SELECT id, ok FROM certificates") == [(certificate, 1)]
    assert await rows(recorder, "SELECT ended_by_command_id FROM sessions WHERE id = 's1'") == await rows(
        recorder, "SELECT id FROM commands"
    )
    assert await rows(recorder, "SELECT id FROM commands") == [(2,)]
    whose = "SELECT identities.name FROM sessions JOIN identities ON identity_id = identities.id ORDER BY sessions.id"
    assert await rows(recorder, whose) == [("laptop",), ("other",)]


@pytest.mark.parametrize(
    ("path", "kept"),
    [("/page", "/page"), ("/in/link/k3y", "/in/link/"), ("/in/link/k3y/link/x", "/in/link/")],
)
def test_a_request_is_recorded_without_its_link_key(path: str, kept: str) -> None:
    assert record._path(path) == kept


def test_bodies_are_kept_squeezed_when_that_comes_out_smaller() -> None:
    text = b"hello " * 100
    assert packed(text) == ("zlib", zlib.compress(text))
    noise = bytes(range(256))
    assert packed(noise) == ("raw", noise)
    # zlib makes these 17 bytes into 17 bytes, which saves nothing.
    even = bytes.fromhex("0211689c30bf0861616161616161616161")
    assert len(zlib.compress(even)) == len(even)
    assert packed(even) == ("raw", even)


# The recorder


@pytest.fixture
async def recorder(tmp_path: Path) -> AsyncIterator[Recorder]:
    found = Recorder(Database(Storage(str(tmp_path / "w.db"), Record.EVERYTHING, DAY, None, 64), Clock()))
    assert await found.open("0.5.0", "host", "example.com", {"domain": "example.com"}) == set()
    yield found
    await found.close()


async def rows(recorder: Recorder, sql: str) -> list[tuple[Any, ...]]:
    assert recorder._database is not None
    await recorder._database.flush()
    return await recorder._database.read(sql)


def session(identity: Identity = ALICE, number: int = 1) -> Session:
    return Session(f"s{number}", identity, "websocket", PEER, NOW, lambda reason: None)


async def test_a_run_is_recorded_from_start_to_stop(tmp_path: Path) -> None:
    path = tmp_path / "w.db"
    record = Recorder(Database(Storage(str(path)), Clock()))
    await record.open("0.5.0", "host", "example.com", {"domain": "example.com"})
    await record.close()
    assert peek(path, "SELECT * FROM runs") == [
        (1, "0.5.0", "host", "example.com", '{"domain":"example.com"}', NOW, NOW)
    ]


async def test_a_recorder_keeps_what_its_storage_says(recorder: Recorder) -> None:
    assert (recorder.history, recorder.traffic, recorder.traffic_max) == (True, True, 64)


async def test_without_a_database_nothing_is_written() -> None:
    record = Recorder()
    assert await record.open("0.5.0", "host", "example.com", {}) == set()
    assert (record.history, record.traffic, record.traffic_max, record.now()) == (False, False, 0, 0)
    record.auth("websocket", "token", PEER, ALICE, None)
    record.session_opened(session(), True, {})
    assert record.tunnel_opened(session(), None, False, {}) == 0
    assert record.connection_opened("http", PEER, None) is None
    await record.close()


async def test_logins_identities_and_tokens(recorder: Recorder) -> None:
    recorder.auth("websocket", "token", PEER, ALICE, None)
    recorder.auth("ssh", "key", PEER, None, "refused")
    recorder.auth("websocket", "token", PEER, dataclasses.replace(ALICE, name="alice2"), None)
    assert await rows(recorder, "SELECT id, method, subject, name FROM identities") == [
        (1, "token", "alice-token", "alice2")
    ]
    assert await rows(recorder, "SELECT * FROM tokens") == [
        ("t1", 1, "alice", '["alice"]', NOW + DAY, NOW, NOW, None, None)
    ]
    assert await rows(
        recorder, "SELECT transport, method, address, port, ok, identity_id, reason FROM auth_attempts"
    ) == [
        ("websocket", "token", PEER.host, PEER.port, 1, 1, None),
        ("ssh", "key", PEER.host, PEER.port, 0, None, "refused"),
        ("websocket", "token", PEER.host, PEER.port, 1, 1, None),
    ]


async def test_a_token_any_name_may_use_is_kept_as_such(recorder: Recorder) -> None:
    recorder.auth("websocket", "token", PEER, Identity("ci", "token", "ci-token", token="t2"), None)
    assert await rows(recorder, "SELECT id, names, expires_at FROM tokens") == [("t2", None, None)]


async def test_denied_tokens_are_kept_for_the_next_run(tmp_path: Path) -> None:
    path = str(tmp_path / "w.db")
    first = Recorder(Database(Storage(path), Clock()))
    await first.open("0.5.0", "host", "example.com", {})
    first.auth("websocket", "token", PEER, ALICE, None)
    first.deny("t1", LAPTOP)
    first.deny("t9", LAPTOP)
    await first.close()
    second = Recorder(Database(Storage(path), Clock()))
    assert await second.open("0.5.0", "host", "example.com", {}) == {"t1", "t9"}
    assert await rows(second, "SELECT id, revoked_at, revoked_by_identity_id FROM tokens ORDER BY id") == [
        ("t1", NOW, 2), ("t9", NOW, 2),
    ]  # fmt: skip
    second.auth("websocket", "key", PEER, LAPTOP, None)
    assert await rows(second, "SELECT count(*) FROM identities") == [(2,)]
    await second.close()


async def test_sessions_open_and_end(recorder: Recorder) -> None:
    recorder.auth("websocket", "token", PEER, ALICE, None)
    first, second = session(), session(LAPTOP, 2)
    recorder.session_opened(first, False, {"version": "0.5.0", "platform": "macOS"})
    recorder.session_opened(second, True, {})
    command = recorder.command(second, "kick", {"who": "alice", "type": "kick"})
    recorder.answered(command, {"sessions": []})
    recorder.answered(None, {"lost": True})
    recorder.session_closed(first, "ended by laptop", command)
    recorder.session_closed(second, None)
    assert await rows(
        recorder,
        "SELECT id, identity_id, token_id, transport, admin, address, client_version, client_platform, expires_at, "
        "started_at, ended_at, end_reason, ended_by_command_id FROM sessions ORDER BY id",
    ) == [
        ("s1", 1, "t1", "websocket", 0, PEER.host, "0.5.0", "macOS", NOW + DAY, NOW, NOW, "ended by laptop", 1),
        ("s2", 2, None, "websocket", 1, PEER.host, None, None, None, NOW, NOW, None, None),
    ]
    assert await rows(recorder, "SELECT session_id, kind, request, answer FROM commands") == [
        ("s2", "kick", '{"type":"kick","who":"alice"}', '{"sessions":[]}')
    ]


def lock_of(recorder: Recorder) -> Lock:
    lock = Lock(bytes(32), DEFAULTS, "foo.example.com", False, False, Locking(), lambda state: None, Clock())
    lock.add_password("alice", "pw")
    lock.mint("bob", "a.foo.example.com", "/x", NOW + DAY, 2)
    return lock


async def test_tunnels_their_names_and_their_locks(recorder: Recorder) -> None:
    recorder.auth("websocket", "token", PEER, ALICE, None)
    one = session()
    recorder.session_opened(one, False, {})
    lock = lock_of(recorder)
    recorder.lock_made(lock, ALICE, {"path": "/in"})
    tunnel = recorder.tunnel_opened(one, lock, False, {"foo": "http://foo.example.com"})
    recorder.tunnel_rejected(one, ["bar", "bar", "*.bar"], "bar: taken")
    recorder.tunnel_closed(tunnel)
    lock.end("alice")
    entry = lock.entries[f"{PASSWORD}:alice"]
    entry.used, entry.seen = NOW - 2, NOW - 1
    command = recorder.command(one, "link", {})
    recorder.credential(lock, entry, command)
    # Seen again by what it does later, it still says which command made it.
    recorder.credential(lock, entry)
    recorder.lock_ended(lock)
    found = await rows(recorder, "SELECT id, session_id, lock_id, indexed, opened_at, closed_at, rejected FROM tunnels")
    assert found == [
        (1, "s1", lock.id, 0, NOW, NOW, None), (2, "s1", None, 0, NOW, NOW, "bar: taken"),
    ]  # fmt: skip
    assert await rows(recorder, "SELECT * FROM tunnel_names ORDER BY tunnel_id, name") == [
        (1, "foo", "http://foo.example.com"), (2, "*.bar", None), (2, "bar", None),
    ]  # fmt: skip
    assert await rows(recorder, "SELECT id, identity_id, home, on_domain, settings, ended_at FROM locks") == [
        (lock.id, 1, "foo.example.com", 0, '{"path":"/in"}', NOW)
    ]
    assert await rows(
        recorder,
        "SELECT id, kind, label, link_host, link_path, max_uses, uses, last_used_at, last_seen_at, expires_at, "
        "created_by_command_id, ended_at FROM credentials ORDER BY id",
    ) == [
        (credential_id(lock, lock.entries[f"{LINK}:bob"]), "link", "bob", "a.foo.example.com", "/x", 2, 0, None, None,
         NOW + DAY, None, None),
        (credential_id(lock, entry), "password", "alice", None, None, None, 0, NOW - 2, NOW - 1, None, command, NOW),
    ]  # fmt: skip
    recorder.lock_made(lock, ALICE, {"path": "/in"})
    assert await rows(recorder, "SELECT ended_at FROM locks") == [(None,)]


async def test_what_happens_at_a_lock(recorder: Recorder) -> None:
    recorder.auth("websocket", "token", PEER, ALICE, None)
    recorder.session_opened(session(), False, {})
    lock = lock_of(recorder)
    recorder.lock_made(lock, ALICE, {})
    bob = lock.entries[f"{LINK}:bob"]
    request = parse_request(b"GET /x HTTP/1.1\r\nHost: foo.example.com\r\nUser-Agent: Chat/1\r\n\r\n")
    recorder.link_opened(lock, bob, PEER, request, used=False)
    recorder.link_opened(lock, bob, PEER, request, used=True)
    recorder.login_attempt(lock, "form", "eve", None, PEER, request, "wrong-password")
    recorder.login_attempt(lock, "link", "bob", bob, PEER, request, None)
    recorder.handoff(lock, bob, "d" * 64, "a.foo.example.com")
    recorder.redeemed("d" * 64)
    bob_id = credential_id(lock, bob)
    assert await rows(recorder, "SELECT credential_id, address, user_agent, outcome FROM link_opens") == [
        (bob_id, PEER.host, "Chat/1", "shown"), (bob_id, PEER.host, "Chat/1", "used"),
    ]  # fmt: skip
    assert await rows(recorder, "SELECT via, label, credential_id, user_agent, ok, reason FROM login_attempts") == [
        ("form", "eve", None, "Chat/1", 0, "wrong-password"), ("link", "bob", bob_id, "Chat/1", 1, None),
    ]  # fmt: skip
    assert await rows(recorder, "SELECT * FROM handoff_codes") == [("d" * 64, bob_id, "a.foo.example.com", NOW, NOW)]


async def test_visitors_their_requests_and_the_bytes(recorder: Recorder) -> None:
    recorder.auth("websocket", "token", PEER, ALICE, None)
    one = session()
    recorder.session_opened(one, False, {})
    lock = lock_of(recorder)
    recorder.lock_made(lock, ALICE, {})
    tunnel = recorder.tunnel_opened(one, lock, False, {})
    connection = recorder.connection_opened("https", PEER, "10.0.0.1")
    assert connection == 1
    page = parse_request(
        b"GET /login/link/SECRET?x=1 HTTP/1.1\r\nHost: foo.example.com\r\nReferer: r\r\nUser-Agent: UA/2\r\n\r\n"
    )
    recorder.request(connection, page, lock, lock.entries[f"{PASSWORD}:alice"], 200)
    recorder.request(connection, parse_request(b"GET / HTTP/1.1\r\nHost: foo.example.com\r\n\r\n"), None, None, None)
    recorder.traffic_chunk(connection, 0, IN, 3, b"hello " * 20)
    recorder.traffic_chunk(connection, 1, OUT, 5, b"\x00\x01")
    recorder.connection_closed(connection, tunnel, 120, 2, 7, True)
    assert await rows(recorder, "SELECT * FROM connections") == [
        (1, 1, NOW, 7, "https", PEER.host, PEER.port, "10.0.0.1", tunnel, 120, 2, 1)
    ]
    assert await rows(
        recorder, "SELECT method, host, path, query, user_agent, referer, lock_id, credential_id, status FROM requests"
    ) == [
        ("GET", "foo.example.com", "/login/link/", "x=1", "UA/2", "r", lock.id,
         credential_id(lock, lock.entries[f"{PASSWORD}:alice"]), 200),
        ("GET", "foo.example.com", "/", None, None, None, None, None, None),
    ]  # fmt: skip
    found = await rows(recorder, "SELECT seq, direction, at_ms, encoding, size, data FROM traffic")
    assert found == [(0, "in", 3, "zlib", 120, zlib.compress(b"hello " * 20)), (1, "out", 5, "raw", 2, b"\x00\x01")]


async def test_certificates_and_dns(recorder: Recorder) -> None:
    good, bad = recorder.certificate_requested("foo.example.com"), recorder.certificate_requested("bar.example.com")
    assert good is not None
    assert bad is not None
    recorder.certificate_finished(good, None)
    recorder.certificate_finished(bad, "rate limited")
    recorder.dns_change("cname", "*.foo.example.com", "example.com", None)
    recorder.dns_change("create-txt", "_acme-challenge.example.com", "v", "denied")
    assert await rows(recorder, "SELECT parent, requested_at, finished_at, ok, error FROM certificates") == [
        ("foo.example.com", NOW, NOW, 1, None), ("bar.example.com", NOW, NOW, 0, "rate limited"),
    ]  # fmt: skip
    assert await rows(recorder, "SELECT action, record, value, ok, error FROM dns_changes") == [
        ("cname", "*.foo.example.com", "example.com", 1, None),
        ("create-txt", "_acme-challenge.example.com", "v", 0, "denied"),
    ]


async def test_log_lines_but_not_the_records_own(recorder: Recorder) -> None:
    handler = Handler(recorder)
    assert handler.level == logging.INFO
    for name in ("wildburrow.server", "wildburrow.store.database", "asyncio"):
        handler.emit(logging.LogRecord(name, logging.WARNING, __file__, 1, "%s happened", ("it",), None))
    assert await rows(recorder, "SELECT level, logger, message FROM logs") == [
        ("WARNING", "wildburrow.server", "it happened")
    ]


@pytest.fixture
async def minimal(tmp_path: Path) -> AsyncIterator[Recorder]:
    found = Recorder(Database(Storage(str(tmp_path / "w.db"), Record.MINIMAL), Clock()))
    await found.open("0.5.0", "host", "example.com", {})
    yield found
    await found.close()


async def test_minimal_keeps_only_whats_live(minimal: Recorder) -> None:
    assert (minimal.history, minimal.traffic) == (False, False)
    one = session()
    minimal.auth("websocket", "token", PEER, ALICE, None)
    minimal.auth("websocket", "token", PEER, None, "refused")
    minimal.session_opened(one, False, {})
    lock = lock_of(minimal)
    minimal.lock_made(lock, ALICE, {})
    tunnel = minimal.tunnel_opened(one, lock, False, {"foo": "http://foo.example.com"})
    assert minimal.command(one, "names", {}) is None
    assert minimal.connection_opened("http", PEER, None) is None
    assert minimal.certificate_requested("foo.example.com") is None
    minimal.tunnel_rejected(one, ["bar"], "taken")
    request = parse_request(b"GET / HTTP/1.1\r\nHost: foo.example.com\r\n\r\n")
    minimal.login_attempt(lock, "form", "eve", None, PEER, request, "wrong-password")
    minimal.link_opened(lock, lock.entries[f"{LINK}:bob"], PEER, request, used=False)
    minimal.dns_change("cname", "x", "y", None)
    minimal.log(logging.LogRecord("wildburrow.server", logging.INFO, __file__, 1, "x", (), None))
    assert await rows(minimal, "SELECT count(*) FROM tunnels") == [(1,)]
    assert await rows(minimal, "SELECT count(*) FROM credentials") == [(2,)]
    minimal.tunnel_closed(tunnel)
    assert await rows(minimal, "SELECT count(*) FROM tunnels") == [(0,)]
    minimal.lock_ended(lock)
    minimal.session_closed(one, None)
    for table in ("sessions", "tunnels", "locks", "credentials", "auth_attempts", "commands", "login_attempts",
                  "link_opens", "logs", "dns_changes"):  # fmt: skip
        assert await rows(minimal, f"SELECT count(*) FROM {table}") == [(0,)], table  # noqa: S608
    assert await rows(minimal, "SELECT count(*) FROM identities") == [(1,)]


def test_tunnels_without_a_session_go_unrecorded() -> None:
    assert FakeTunnel(ALICE).records == []
