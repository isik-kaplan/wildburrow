"""Questions for the interactive commands, which run when a command gets no options in a terminal."""

import getpass
import os
import sys
from collections.abc import Callable, Mapping
from typing import Any

import click

from wildburrow.config import PREFIX, TRUE

NO_INPUT = f"{PREFIX}NO_INPUT"
# Where the prompts read and draw; tests point them at a pipe.
IO: dict[str, Any] = {}
# Holds NO_INPUT once --no-input is given.
OFF: set[str] = set()

type Check = Callable[[str], str | None]


def off() -> bool:
    """Whether --no-input or WILDBURROW_NO_INPUT turned questions off."""
    return NO_INPUT in OFF or (NO_INPUT in os.environ and os.environ[NO_INPUT].strip().lower() in TRUE)


def interactive() -> bool:
    return not off() and sys.stdin.isatty() and sys.stdout.isatty()


def turn_off() -> None:
    OFF.add(NO_INPUT)


def password(prompt: str) -> str:
    """The password to log in with, asked without echo unless questions are off."""
    if off():
        raise click.ClickException(f"a password is needed, and questions are off (--no-input or {NO_INPUT})")
    return getpass.getpass(prompt)


def required(answer: str) -> str | None:
    return None if answer.strip() else "required"


def port(answer: str) -> str | None:
    return None if answer.strip().isdigit() and 0 < int(answer) < 1 << 16 else "a port number"


def _validator(check: Check | None) -> Callable[[str], bool | str]:
    return lambda answer: True if check is None else check(answer) or True


def _answer(question: Any) -> Any:
    try:
        return question.unsafe_ask()
    except KeyboardInterrupt:
        raise click.Abort from None


def text(message: str, default: str = "", check: Check | None = None) -> str:
    import questionary

    return _answer(questionary.text(message, default=default, validate=_validator(check), **IO)).strip()


def secret(message: str, check: Check | None = None) -> str:
    import questionary

    return _answer(questionary.password(message, validate=_validator(check), **IO)).strip()


def choose[T](message: str, choices: Mapping[T, str], default: T) -> T:
    """`choices` maps each value to the line shown for it."""
    import questionary

    if default not in choices:
        raise ValueError(f"default {default!r} is not one of the choices")

    options = [questionary.Choice(title, value) for value, title in choices.items()]
    return _answer(questionary.select(message, choices=options, default=default, **IO))


def confirm(message: str, default: bool = True) -> bool:
    import questionary

    if not isinstance(default, bool):
        raise TypeError(f"default must be True or False, not {default!r}")

    return _answer(questionary.confirm(message, default=default, **IO))
