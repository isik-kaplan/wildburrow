"""Questions for the interactive commands, which run when a command gets no options in a terminal."""

import sys
from collections.abc import Callable, Mapping
from typing import Any

import click

# Where the prompts read and draw; tests point them at a pipe.
IO: dict[str, Any] = {}

type Check = Callable[[str], str | None]


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


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


def choose(message: str, choices: Mapping[str, str], default: str) -> str:
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
