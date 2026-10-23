import asyncio
from pathlib import Path

import pytest

from wildburrow.auth.base import Authenticator
from wildburrow.core.context import ServerContext
from wildburrow.transports import ssh


class Connection:
    def __init__(self) -> None:
        self.closed = asyncio.Event()

    def close(self) -> None:
        self.closed.set()


class Output:
    def __init__(self) -> None:
        self.text = ""

    def write(self, text: str) -> None:
        self.text += text


class Process:
    def __init__(self, closes: bool) -> None:
        self.stdout = Output()
        self.exits: list[int] = []
        self._closes = closes

    def exit(self, code: int) -> None:
        self.exits.append(code)

    async def wait_closed(self) -> None:
        if not self._closes:
            await asyncio.Event().wait()


def client(tmp_path: Path, process: Process | None) -> tuple[ssh._Client, Connection]:
    ended = ssh._Client(ServerContext("example.com", 5, tmp_path, Authenticator([])), set())
    ended._conn = connection = Connection()  # type: ignore[assignment]
    if process is not None:
        ended.attach(process)  # type: ignore[arg-type]
    return ended, connection


async def test_the_reason_goes_out_before_the_connection_closes(tmp_path: Path) -> None:
    process = Process(closes=True)
    ended, connection = client(tmp_path, process)
    ended.end("ended by laptop")
    assert (process.stdout.text, process.exits, connection.closed.is_set()) == ("closed: ended by laptop\n", [1], False)
    async with asyncio.timeout(1):
        await connection.closed.wait()


async def test_a_client_that_keeps_its_session_open_is_dropped_anyway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ssh, "CLOSE_GRACE_SECONDS", 0.01)
    ended, connection = client(tmp_path, Process(closes=False))
    ended.end("the token expired")
    async with asyncio.timeout(1):
        await connection.closed.wait()


async def test_without_a_session_the_connection_closes_at_once(tmp_path: Path) -> None:
    ended, connection = client(tmp_path, None)
    ended.end("ended by laptop")
    assert connection.closed.is_set()
    assert ended._pending == ["closed: ended by laptop"]
