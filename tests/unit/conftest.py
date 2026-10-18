import io
import os
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

import pytest
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import PipeInput, create_pipe_input
from prompt_toolkit.output.plain_text import PlainTextOutput

from wildburrow.auth.base import Authenticator
from wildburrow.cli import ask
from wildburrow.core.context import ServerContext


@pytest.fixture
def ctx(tmp_path: Path) -> ServerContext:
    return ServerContext("example.com", 5, tmp_path, Authenticator([]))


ENTER = "\r"
DOWN = "\x1b[B"
CTRL_C = "\x03"


class _Screen(PlainTextOutput):
    """Wide enough that no prompt wraps."""

    def get_size(self) -> Size:
        return Size(rows=40, columns=1000)


class Typist:
    """Types into the interactive prompts as if into a terminal, and reads back what they showed."""

    def __init__(self, stack: ExitStack) -> None:
        self.stack = stack
        self.screen = io.StringIO()

    def __call__(self, *keys: str) -> None:
        """Types `keys` into a new session that then ends, so a prompt asking for more fails rather than waits."""
        keyboard: PipeInput = self.stack.enter_context(create_pipe_input())
        keyboard.send_text("".join(keys))
        keyboard.close()
        ask.IO.update(input=keyboard, output=_Screen(self.screen))

    def showed(self, *lines: str) -> bool:
        """Whether these appeared, in this order: each prompt is left showing its question and then its answer."""
        text, start = self.screen.getvalue(), 0
        for line in lines:
            start = text.find(line + "\r\n", start)
            if start < 0:
                return False
        return True


@pytest.fixture
def typed(monkeypatch: pytest.MonkeyPatch) -> Iterator[Typist]:
    with ExitStack() as stack:
        monkeypatch.setattr(ask, "IO", {})
        monkeypatch.setattr(ask, "interactive", lambda: True)
        yield Typist(stack)


@pytest.fixture
def no_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ask, "interactive", lambda: False)


@pytest.fixture(autouse=True)
def no_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing under test may replace the test process, least of all with sudo where it needs no password."""

    def execvp(file: str, args: list[str]) -> None:
        pytest.fail(f"tried to exec {args}")

    monkeypatch.setattr(os, "execvp", execvp)
