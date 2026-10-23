import io

import click
import pytest

from tests.unit.conftest import CTRL_C, DOWN, ENTER, Typist
from wildburrow.cli import ask


class Terminal(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


@pytest.mark.parametrize(
    ("stdin", "stdout", "expected"), [(True, True, True), (True, False, False), (False, True, False)]
)
def test_only_a_terminal_on_both_ends_is_interactive(
    monkeypatch: pytest.MonkeyPatch, stdin: bool, stdout: bool, expected: bool
) -> None:
    monkeypatch.setattr("sys.stdin", Terminal(stdin))
    monkeypatch.setattr("sys.stdout", Terminal(stdout))
    assert ask.interactive() is expected


@pytest.mark.parametrize("value", ["1", "true", " YES ", "on"])
def test_no_input_in_the_environment_turns_questions_off(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr("sys.stdin", Terminal(True))
    monkeypatch.setattr("sys.stdout", Terminal(True))
    monkeypatch.setenv(ask.NO_INPUT, value)
    assert ask.interactive() is False
    with pytest.raises(click.ClickException, match=r"^a password is needed, and questions are off \(--no-input or "):
        ask.password("password: ")


@pytest.mark.parametrize("value", ["", "0", "false", "no", "maybe"])
def test_other_no_input_values_leave_questions_on(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr("sys.stdin", Terminal(True))
    monkeypatch.setattr("sys.stdout", Terminal(True))
    monkeypatch.setenv(ask.NO_INPUT, value)
    monkeypatch.setattr("getpass.getpass", lambda prompt: f"typed at {prompt}")
    assert ask.interactive() is True
    assert ask.password("p: ") == "typed at p: "


def test_turning_questions_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", Terminal(True))
    monkeypatch.setattr("sys.stdout", Terminal(True))
    ask.turn_off()
    assert ask.interactive() is False
    with pytest.raises(click.ClickException):
        ask.password("password: ")


@pytest.mark.parametrize(("answer", "problem"), [("x", None), ("  ", "required"), ("", "required")])
def test_required_answers(answer: str, problem: str | None) -> None:
    assert ask.required(answer) == problem


@pytest.mark.parametrize(
    ("answer", "problem"),
    [("1", None), (" 22 ", None), ("65535", None), ("0", "a port number"), ("65536", "a port number"),
     ("x", "a port number"), ("", "a port number"), ("-1", "a port number")],
)  # fmt: skip
def test_port_answers(answer: str, problem: str | None) -> None:
    assert ask.port(answer) == problem


def test_text_strips_and_keeps_the_default(typed: Typist) -> None:
    typed("  spaced  ", ENTER, ENTER)
    assert ask.text("first") == "spaced"
    assert ask.text("second", "kept") == "kept"
    assert typed.showed("? first   spaced  ", "? second kept")


def test_text_asks_again_until_the_check_passes(typed: Typist) -> None:
    seen: list[str] = []
    typed("bad", ENTER, "\b\b\bgood", ENTER)
    assert ask.text("q", check=lambda answer: seen.append(answer) or (None if answer == "good" else "no")) == "good"
    assert seen == ["bad", "good"]


def test_secret_is_checked_too(typed: Typist) -> None:
    typed(ENTER, "s3cret ", ENTER)
    assert ask.secret("token", lambda answer: None if answer else "required") == "s3cret"
    assert typed.showed("? token *******")


def test_choose_returns_the_value_starting_at_the_default(typed: Typist) -> None:
    typed(ENTER, DOWN, ENTER)
    choices = {"a": "first", "b": "second", "": "none"}
    assert ask.choose("pick", choices, "b") == "b"
    assert ask.choose("pick", choices, "b") == ""
    assert typed.showed("? pick second", "? pick none")


def test_choose_needs_its_default_among_the_choices(typed: Typist) -> None:
    with pytest.raises(ValueError, match=r"^default 'c' is not one of the choices$"):
        ask.choose("pick", {"a": "first"}, "c")


@pytest.mark.parametrize(
    ("keys", "default", "expected"), [("y", False, True), ("n", True, False), (ENTER, False, False)]
)
def test_confirm(typed: Typist, keys: str, default: bool, expected: bool) -> None:
    typed(keys)
    assert ask.confirm("sure?", default) is expected
    assert typed.showed(f"? sure? {'Yes' if expected else 'No'}")


def test_confirm_needs_a_yes_or_no_default(typed: Typist) -> None:
    with pytest.raises(TypeError, match=r"^default must be True or False, not None$"):
        ask.confirm("sure?", None)  # type: ignore[arg-type]


def test_confirm_defaults_to_yes(typed: Typist) -> None:
    typed(ENTER)
    assert ask.confirm("sure?") is True


def test_ctrl_c_aborts(typed: Typist) -> None:
    typed(CTRL_C)
    with pytest.raises(click.Abort):
        ask.confirm("sure?")
