import io
from collections.abc import Iterator
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

    def __init__(self, keyboard: PipeInput) -> None:
        self.keyboard = keyboard
        self.screen = io.StringIO()

    def __call__(self, *keys: str) -> None:
        self.keyboard.send_text("".join(keys))

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
    with create_pipe_input() as keyboard:
        typist = Typist(keyboard)
        monkeypatch.setattr(ask, "IO", {"input": keyboard, "output": _Screen(typist.screen)})
        monkeypatch.setattr(ask, "interactive", lambda: True)
        yield typist


@pytest.fixture
def no_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ask, "interactive", lambda: False)
