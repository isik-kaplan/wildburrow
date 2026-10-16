import asyncio
import os
import signal
import sys
from pathlib import Path

import pytest

from wildburrow.client import ssh
from wildburrow.client.config import ClientConfig
from wildburrow.client.retry import Backoff

SCRIPT = """
import sys
from pathlib import Path
counter = Path(sys.argv[1])
attempt = int(counter.read_text() if counter.exists() else 0) + 1
counter.write_text(str(attempt))
print(f"attempt {attempt}", flush=True)
ready, code = sys.argv[1 + attempt].split(",")
if ready == "1":
    print("ready: http://app.example", flush=True)
sys.exit(int(code))
"""


def attempts(tmp_path: Path, *outcomes: str) -> list[str]:
    return [sys.executable, "-c", SCRIPT, str(tmp_path / "count"), *outcomes]


async def test_only_sessions_that_came_up_are_retried(tmp_path: Path) -> None:
    lines: list[str] = []
    command = attempts(tmp_path, "1,255", "0,255", "1,255", "0,7")
    assert await ssh.tunnel(command, lines.append, backoff=Backoff(0.001, 0.002)) == 7
    assert lines == [
        "attempt 1",
        "ready: http://app.example",
        "connection lost; retrying in 0.001s",
        "attempt 2",
        "connection lost; retrying in 0.002s",
        "attempt 3",
        "ready: http://app.example",
        "connection lost; retrying in 0.001s",
        "attempt 4",
    ]


async def test_reconnecting_can_be_turned_off(tmp_path: Path) -> None:
    lines: list[str] = []
    assert await ssh.tunnel(attempts(tmp_path, "1,255", "1,0"), lines.append, reconnect=False) == 255
    assert lines == ["attempt 1", "ready: http://app.example"]


@pytest.mark.parametrize("outcome", ["0,255", "1,1", "1,0"])
async def test_other_exits_end_the_client(tmp_path: Path, outcome: str) -> None:
    lines: list[str] = []
    assert await ssh.tunnel(attempts(tmp_path, outcome), lines.append) == int(outcome.split(",")[1])
    assert not any("retrying" in line for line in lines)


async def test_cancelling_terminates_ssh() -> None:
    lines: list[str] = []
    command = [sys.executable, "-c", "import os, time; print(os.getpid(), flush=True); time.sleep(60)"]
    task = asyncio.create_task(ssh.tunnel(command, lines.append))
    async with asyncio.timeout(10):
        while not lines:
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(ProcessLookupError):
        os.kill(int(lines[0]), 0)


def test_run_reports_exit_codes(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[tuple] = []

    async def finished(command: list[str], out, backoff: Backoff, reconnect: bool) -> int:
        seen.append((command, backoff.next(), backoff.next(), reconnect))
        out("ready: http://app.example")
        return 3

    monkeypatch.setattr(ssh, "tunnel", finished)
    config = ClientConfig("tunnel.example.com", 2222, "me", reconnect=False, retry_delay=2, retry_max=3)
    assert ssh.run(config, 3000, ["app"], "localhost") == 3
    assert seen == [(ssh.ssh_command(config, 3000, ["app"], "localhost"), 2, 3, False)]
    assert capsys.readouterr().err == "ready: http://app.example\n"


def test_run_stops_on_sigterm(monkeypatch: pytest.MonkeyPatch) -> None:
    async def terminated(command: list[str], out, **kwargs) -> int:
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(10)
        raise AssertionError("not cancelled")

    monkeypatch.setattr(ssh, "tunnel", terminated)
    assert ssh.run(ClientConfig("s"), 3000, ["app"], "localhost") == ssh.TERMINATED


def test_run_stops_on_ctrl_c(monkeypatch: pytest.MonkeyPatch) -> None:
    async def interrupted(command: list[str], out, **kwargs) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(ssh, "tunnel", interrupted)
    assert ssh.run(ClientConfig("s"), 3000, ["app"], "localhost") == 130
