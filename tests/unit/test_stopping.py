import asyncio
import os
import signal

import pytest

from wildburrow.stopping import Stopping, closing


def test_a_hung_up_terminal_still_stops() -> None:
    said: list[signal.Signals] = []

    def say(sig: signal.Signals, again: bool) -> None:
        said.append(sig)
        raise OSError(5, "Input/output error")

    stopping = Stopping(say)

    async def go() -> None:
        stopping.install()
        os.kill(os.getpid(), signal.SIGHUP)
        await asyncio.sleep(10)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(go())
    assert said == [signal.SIGHUP]
    assert (stopping.signal, stopping.code()) == (signal.SIGHUP, 129)


def test_the_first_signal_is_the_one_that_counts() -> None:
    said: list[tuple[signal.Signals, bool]] = []
    stopping = Stopping(lambda sig, again: said.append((sig, again)))

    async def go() -> None:
        stopping.install()
        os.kill(os.getpid(), signal.SIGTERM)
        try:
            await asyncio.sleep(10)
        finally:
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(10)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(go())
    assert said == [(signal.SIGTERM, False), (signal.SIGINT, True)]
    assert stopping.code() == 143


def test_clients_say_why_they_close() -> None:
    assert closing(signal.SIGINT, again=False) == "interrupted: closing the tunnel (ctrl+c again to quit now)"
    assert closing(signal.SIGTERM, again=False) == "terminated: closing the tunnel"
    assert closing(signal.SIGHUP, again=False) == "hung up: closing the tunnel"
    assert closing(signal.SIGINT, again=True) == "quitting now"
