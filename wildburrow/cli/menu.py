"""What bare `wildburrow` offers in a terminal: each choice asks for what it needs and runs its command."""

from collections.abc import Callable

from wildburrow.cli import ask, client, service, tokens
from wildburrow.core.names import ANY
from wildburrow.service import ServiceError
from wildburrow.service import manager as find_manager

DURATIONS = "30m, 12h, 7d, 2w or never"


def _tunnel() -> int:
    port = int(ask.text("Local port", "", ask.port))
    names = ask.text("Names, separated by spaces (* for any one label, as in *.myapp)", "", ask.required)
    return client._connect(port, tuple(names.split()), None, "localhost", {})


def _login() -> int:
    return client._login(None, None, {})


def _token() -> int:
    name = ask.text("Who is it for", "", ask.required)
    names = ask.text(f"Names they may claim, comma-separated (or {ANY})", f"{name},*.{name}", ask.required)
    expires = ask.text(f"Good for ({DURATIONS})", tokens.DEFAULT_EXPIRY, ask.required)
    return tokens._token(name, names, expires, None, None, False, False)


def _sessions() -> int:
    found = client.listed(None)
    if not found or not ask.confirm("End one of them?", default=False):
        return 0
    choices = {entry["id"]: f"{entry['id']}: {client.who(entry)}" for entry in found}
    return client.end(None, {"session": ask.choose("Which?", choices, found[0]["id"])})


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
