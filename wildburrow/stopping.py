"""Stopping a long-running command on a signal: the first lets it clean up, the next cuts the clean-up short."""

import asyncio
import contextlib
import signal
from collections.abc import Callable

# ctrl+c, a service manager's stop, and the terminal closing.
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
WHY = {signal.SIGINT: "interrupted", signal.SIGTERM: "terminated", signal.SIGHUP: "hung up"}


class Stopping:
    """Cancels the task it's installed in on any of SIGNALS, telling `say` why, and again on a repeat."""

    def __init__(self, say: Callable[[signal.Signals, bool], None]) -> None:
        self._say = say
        self.signal: signal.Signals | None = None

    def install(self) -> None:
        task = asyncio.current_task()
        assert task is not None  # noqa: S101
        loop = asyncio.get_running_loop()
        for sig in SIGNALS:
            loop.add_signal_handler(sig, self._on, sig, task)

    def _on(self, sig: signal.Signals, task: asyncio.Task[object]) -> None:
        again = self.signal is not None
        self.signal = self.signal or sig
        # A hung-up terminal can't be written to any more.
        with contextlib.suppress(OSError):
            self._say(sig, again)
        task.cancel()

    def code(self) -> int:
        """The exit code of a command its signal stopped: 128 and the signal's number."""
        assert self.signal is not None  # noqa: S101
        return 128 + self.signal


def closing(sig: signal.Signals, again: bool) -> str:
    """What a client says when a signal stops its tunnel."""
    if again:
        return "quitting now"
    hint = " (ctrl+c again to quit now)" if sig == signal.SIGINT else ""
    return f"{WHY[sig]}: closing the tunnel{hint}"
