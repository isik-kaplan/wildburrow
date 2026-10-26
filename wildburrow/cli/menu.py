"""What bare `wildburrow` offers in a terminal: each choice asks for what it needs and runs its command."""

from collections.abc import Callable

import click

from wildburrow.cli import ask, client, service, tokens
from wildburrow.service import ServiceError
from wildburrow.service import manager as find_manager


def _alone(command: click.Command, *args: str) -> int:
    """Runs `command` given nothing, so it asks for what it needs."""
    with command.make_context(command.name, list(args), parent=click.get_current_context()) as ctx:
        return command.invoke(ctx)


def _tunnel() -> int:
    return _alone(client.connect)


def _login() -> int:
    return client._login(None, None, {})


def _token() -> int:
    return _alone(tokens.new_token)


def _sessions() -> int:
    return _alone(client.kick)


def _install() -> int:
    return service._install(False, {})


def _edit() -> int:
    return service._edit({})


def _installed() -> bool | None:
    """Whether the server runs here as a service; None where no service manager is supported."""
    try:
        return find_manager().installed()
    except ServiceError:
        return None


def run() -> int:
    actions: dict[Callable[[], int], str] = {
        _tunnel: "Open a tunnel",
        _login: "Log in to a server",
        _token: "Mint a token for someone",
        _sessions: "See or end sessions on the server",
    }
    match _installed():
        case False:
            actions[_install] = "Set up a server here, as a service"
        case True:
            actions[_edit] = "Change the server running here"
    return ask.choose("What do you want to do?", actions, _tunnel)()
