from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.conftest import DOWN, ENTER, Typist
from wildburrow import cli
from wildburrow.cli import ask, menu, service, tokens
from wildburrow.cli import client as client_cli
from wildburrow.cli.output import when
from wildburrow.cli.settings import Tunnel
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, read_config, write_config
from wildburrow.config import PREFIX
from wildburrow.service import ServiceError

SERVER = "tunnel.example.com"
LATER = 2_000_000_000
ALICE = {
    "id": "a1b2c3d4e5f6",
    "who": "alice",
    "via": "token",
    "transport": "websocket",
    "names": ["alice", "*.alice"],
    "since": 1_000_000_000,
    "expires": LATER,
    "token": "3f9a0c4e1b2d7a65",
    "yours": False,
    "from": "203.0.113.4",
}
MINE = {
    "id": "0f0f0f0f0f0f",
    "who": "laptop",
    "via": "key",
    "transport": "ssh",
    "names": [],
    "since": 1_000_000_000,
    "expires": None,
    "token": "",
    "yours": True,
}


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


@pytest.fixture
def logged_in() -> ClientConfig:
    config = ClientConfig(SERVER, transport="websocket", auth="token", token="t")
    write_config(config_path(), config)
    return config


class Server:
    """What `tunnels` and `kick` are answered with, and what they asked."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.listed: list[dict[str, Any]] = []
        self.answer: dict[str, Any] = {"sessions": [], "refused": []}
        self.reach: dict[str, Any] | None = None
        self.asked: list[tuple[ClientConfig, Any]] = []
        monkeypatch.setattr(websocket, "sessions", self.sessions)
        monkeypatch.setattr(websocket, "kick", self.kick)

    async def sessions(self, config: ClientConfig, ask: object) -> tuple[list[dict[str, Any]], dict | None]:
        self.asked.append((config, None, ask))
        return self.listed, self.reach

    async def kick(self, config: ClientConfig, pick: Callable, ask: object) -> dict[str, Any]:
        if isinstance(self.answer, Exception):
            raise self.answer
        self.asked.append((config, pick(self.listed, self.reach), ask))
        return {"reach": self.reach, **self.answer}


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Server:
    return Server(monkeypatch)


def test_tunnels_lists_the_sessions_shown(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    server.listed = [ALICE, MINE]
    monkeypatch.setenv(client_cli.TOKEN_ENV, "from-env")
    assert cli.main(["tunnels"]) == 0
    since = when(1_000_000_000)
    assert capsys.readouterr().out.splitlines() == [
        f"ID            WHO           VIA              NAMES           SINCE{' ' * 17}EXPIRES{' ' * 15}FROM",
        f"a1b2c3d4e5f6  alice         token/websocket  alice, *.alice  {since}  {when(LATER)}  203.0.113.4",
        f"0f0f0f0f0f0f  laptop (you)  key/ssh          -               {since}  -                     -",
    ]
    assert server.asked == [(logged_in.__replace__(token="from-env"), None, ask.password)]


def test_tunnels_with_nothing_to_show(logged_in: ClientConfig, server: Server, capsys) -> None:
    assert cli.main(["tunnels", "--server", "other.example.com"]) == 0
    assert capsys.readouterr().out == "no other sessions you can see\n"
    assert server.asked[0][0].server == "other.example.com"


def test_tunnels_reports_why_it_could_not_ask(
    logged_in: ClientConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def refused(config: ClientConfig, ask: object) -> list:
        raise websocket.ClientError("s runs an older wildburrow; this needs 0.3.0 or later")

    monkeypatch.setattr(websocket, "sessions", refused)
    assert cli.main(["tunnels"]) == 1
    assert capsys.readouterr().err == "s runs an older wildburrow; this needs 0.3.0 or later\n"


def test_tunnels_needs_a_server(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tunnels"]) == 2
    assert capsys.readouterr().err == "no server configured: run `wildburrow login` or pass --server\n"


@pytest.mark.parametrize(
    ("args", "target"),
    [
        (["a1b2c3d4e5f6"], {"session": "a1b2c3d4e5f6"}),
        (["--name", "*.alice"], {"name": "*.alice"}),
        (["--who", "alice"], {"who": "alice"}),
    ],
)
def test_kick_says_what_ended_and_how_it_could_come_back(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], args: list[str], target: dict
) -> None:
    server.listed = [ALICE, MINE]
    server.answer = {"sessions": [ALICE, MINE], "refused": []}
    assert cli.main(["kick", *args]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "ended a1b2c3d4e5f6: alice over websocket, holding alice, *.alice",
        f"  their token 3f9a0c4e1b2d7a65 logs in until {when(LATER)}; to stop it sooner, add the id to "
        f"{PREFIX}AUTH_TOKEN_DENY",
        "ended 0f0f0f0f0f0f: laptop over ssh, holding no names",
    ]
    assert server.asked == [(logged_in, [target], ask.password)]


@pytest.mark.parametrize(
    ("entry", "hint"),
    [
        ({"expires": None}, "their token 3f9a0c4e1b2d7a65 logs in for good; to stop it sooner, add the id to"),
        ({"expires": 1}, None),
        ({"token": "", "via": "key"}, "alice can connect again with the same key"),
        ({"token": "", "via": "password"}, "alice can connect again with the same password"),
        ({"yours": True}, None),
    ],
)
def test_kick_hints_only_where_coming_back_is_possible(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], entry: dict, hint: str | None
) -> None:
    server.answer = {"sessions": [ALICE | entry], "refused": []}
    assert cli.main(["kick", "--who", "alice"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1:] == ([] if hint is None else [lines[1]])
    if hint is not None:
        assert lines[1].startswith(f"  {hint}")


def test_a_token_ending_now_needs_no_hint(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_cli.time, "time", lambda: LATER)
    server.answer = {"sessions": [ALICE], "refused": []}
    assert cli.main(["kick", "--who", "alice"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1
    monkeypatch.setattr(client_cli.time, "time", lambda: LATER - 1)
    assert cli.main(["kick", "--who", "alice"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 2


@pytest.mark.parametrize(
    ("answer", "code", "out", "err"),
    [
        ({"sessions": [], "refused": []}, 1, [], ["no session you can see matches"]),
        ({"sessions": [], "refused": ["b2"]}, 1, [], ["not allowed to end b2"]),
        ({"sessions": [MINE], "refused": ["b2", "c3"]}, 1, ["ended 0f0f0f0f0f0f: laptop over ssh, holding no names"],
         ["not allowed to end b2", "not allowed to end c3"]),
    ],
)  # fmt: skip
def test_kick_reports_what_it_could_not_end(
    logged_in: ClientConfig, server: Server, capsys, answer: dict, code: int, out: list, err: list
) -> None:
    server.answer = answer
    assert cli.main(["kick", "--who", "x"]) == code
    captured = capsys.readouterr()
    assert (captured.out.splitlines(), captured.err.splitlines()) == (out, err)


def test_kick_reports_why_it_could_not_ask(logged_in: ClientConfig, server: Server, capsys) -> None:
    server.answer = websocket.ClientError("authentication failed")
    assert cli.main(["kick", "--who", "alice"]) == 1
    assert capsys.readouterr().err == "authentication failed\n"


def test_kick_asks_the_server_given(logged_in: ClientConfig, server: Server) -> None:
    assert cli.main(["kick", "--who", "a", "--server", "other.example.com"]) == 1
    assert server.asked[0][0] == logged_in.__replace__(server="other.example.com")


def test_kick_needs_a_target_without_a_terminal(server: Server, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["kick"]) == 2
    assert capsys.readouterr().err.splitlines()[-1] == "Error: pass TARGET, --who or --name"
    assert server.asked == []


BOB = ALICE | {"id": "b0b0b0b0b0b0", "who": "bob", "names": ["bob", "alice-app"], "token": ""}


@pytest.mark.parametrize(
    ("args", "targets"),
    [
        (["alice"], [{"session": ALICE["id"]}]),
        (["*.alice", "a1b2c3d4e5f6", "bob"], [{"session": ALICE["id"]}, {"session": BOB["id"]}]),
        (["alice-app", "--who", "x", "--name", "y"], [{"session": BOB["id"]}, {"who": "x"}, {"name": "y"}]),
        (["--who", "a", "--who", "b"], [{"who": "a"}, {"who": "b"}]),
    ],
)
def test_kick_works_out_what_each_target_means(
    logged_in: ClientConfig, server: Server, args: list[str], targets: list[dict[str, str]]
) -> None:
    server.listed = [ALICE, BOB]
    server.answer = {"sessions": [ALICE], "refused": []}
    assert cli.main(["kick", *args]) == 0
    assert [targets for _config, targets, _ask in server.asked] == [targets]


def test_kick_refuses_a_target_that_names_different_sessions(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    server.listed = [ALICE, BOB | {"names": ["alice"]}]
    assert cli.main(["kick", "bob", "alice"]) == 2
    assert capsys.readouterr().err.splitlines() == [
        "alice names different sessions:",
        f"  as identity: {ALICE['id']}",
        f"  as name: {ALICE['id']}, {BOB['id']}",
        "pass --who alice or --name alice to pick one",
    ]
    assert server.asked == []


def test_kick_refuses_a_target_that_names_nothing(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    server.listed = [ALICE]
    assert cli.main(["kick", "alice", "zed"]) == 1
    assert capsys.readouterr().err == "no session you can see matches zed\n"
    assert server.asked == []


def test_a_command_needing_a_server_logs_in_first_in_a_terminal(
    typed: Typist, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    typed(SERVER, ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["tunnels"]) == 0
    assert read_config(config_path()).server == SERVER
    assert server.asked[0][0].server == SERVER
    out = capsys.readouterr().out
    assert out.startswith("Not logged in to a server yet.\n")
    assert f"saved {config_path()}\n" in out


def test_a_given_server_needs_no_login(typed: Typist, server: Server) -> None:
    assert cli.main(["tunnels", "--server", SERVER]) == 0
    assert server.asked[0][0] == ClientConfig(SERVER)
    assert read_config(config_path()) is None


@pytest.fixture
def terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    tty = SimpleNamespace(isatty=lambda: True)
    monkeypatch.setattr(ask, "sys", SimpleNamespace(stdin=tty, stdout=tty))


def test_no_input_never_asks_to_log_in(server: Server, capsys: pytest.CaptureFixture[str], terminal: None) -> None:
    assert ask.interactive()
    assert cli.main(["--no-input", "tunnels"]) == 2
    assert capsys.readouterr().err == "no server configured: run `wildburrow login` or pass --server\n"


class Ran:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[str, tuple]] = []
        for module, name in [
            (client_cli, "_connect"),
            (client_cli, "_login"),
            (tokens, "_token"),
            (service, "_install"),
            (service, "_edit"),
            (client_cli, "end"),
        ]:
            monkeypatch.setattr(module, name, self.recorder(name))

    def recorder(self, name: str):
        def record(*args: object) -> int:
            self.calls.append((name, args))
            return 7

        return record


class Manager:
    def __init__(self, installed: bool | None) -> None:
        self._installed = installed

    def installed(self) -> bool:
        if self._installed is None:
            raise ServiceError("no service manager here")
        return self._installed


@pytest.fixture
def ran(monkeypatch: pytest.MonkeyPatch) -> Ran:
    monkeypatch.setattr(menu, "find_manager", lambda: Manager(False))
    return Ran(monkeypatch)


def test_alone_without_a_terminal_wildburrow_shows_its_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 2
    assert capsys.readouterr().err.startswith("Usage: wildburrow [OPTIONS] [COMMAND] [ARGS]...\n")


def test_alone_with_questions_off_wildburrow_shows_its_help(terminal: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--no-input"]) == 2
    assert "Commands:" in capsys.readouterr().err


def test_the_menu_opens_a_tunnel(typed: Typist, ran: Ran) -> None:
    typed(ENTER, "x", ENTER, "\b", "3000", ENTER, ENTER, "app *.app", ENTER, ENTER, ENTER)
    assert cli.main([]) == 7
    [(name, (port, names, settings))] = ran.calls
    assert (name, port, names) == ("_connect", 3000, ("app", "*.app"))
    assert settings == Tunnel()
    assert typed.showed(
        "? What do you want to do? Open a tunnel",
        "? Local port 3000",
        "? Names, separated by spaces (* for any one label, as in *.myapp) app *.app",
        "? Lock it, so only people you let in see it? No",
        "? Change anything else, such as where the local port listens or how the lock works? No",
    )


def test_the_menu_logs_in(typed: Typist, ran: Ran) -> None:
    typed(DOWN, ENTER)
    assert cli.main([]) == 7
    assert ran.calls == [("_login", (None, None, {}))]


def test_the_menu_mints_a_token(typed: Typist, ran: Ran) -> None:
    typed(DOWN, DOWN, ENTER, ENTER, "bob", ENTER, "\b" * 9, ENTER, "bob,*.bob", ENTER, "\b\b", ENTER, "2h", ENTER)
    assert cli.main([]) == 7
    assert ran.calls == [("_token", ("bob", "bob,*.bob", "2h", None, None, False, False))]
    assert typed.showed(
        "? Who is it for bob",
        "? Names they may claim, comma-separated (or any) bob,*.bob",
        "? Good for (30m, 12h, 7d, 2w or never) 2h",
    )


def test_the_menu_ends_a_session(typed: Typist, ran: Ran, logged_in: ClientConfig, server: Server) -> None:
    server.listed = [ALICE, MINE]
    typed(DOWN, DOWN, DOWN, ENTER, "y", DOWN, ENTER)
    assert cli.main([]) == 7
    [(name, (config, pick))] = ran.calls
    assert (name, config, pick([], None)) == ("end", logged_in, [{"session": "0f0f0f0f0f0f"}])
    assert typed.showed("? End one of them? Yes", "? Which? 0f0f0f0f0f0f: laptop over ssh, holding no names")


def test_the_menu_starts_from_the_first_session(
    typed: Typist, ran: Ran, logged_in: ClientConfig, server: Server
) -> None:
    server.listed = [ALICE, MINE]
    typed(DOWN, DOWN, DOWN, ENTER, "y", ENTER)
    assert cli.main([]) == 7
    [(_name, (_server_given, pick))] = ran.calls
    assert pick([], None) == [{"session": "a1b2c3d4e5f6"}]


def test_the_menu_can_keep_every_session(typed: Typist, ran: Ran, logged_in: ClientConfig, server: Server) -> None:
    server.listed = [ALICE]
    typed(DOWN, DOWN, DOWN, ENTER, ENTER)
    assert cli.main([]) == 0
    assert ran.calls == []
    assert typed.showed("? End one of them? No")


def test_the_menu_with_no_sessions_to_end(typed: Typist, ran: Ran, logged_in: ClientConfig, server: Server) -> None:
    typed(DOWN, DOWN, DOWN, ENTER)
    assert cli.main([]) == 0
    assert ran.calls == []


@pytest.mark.parametrize(
    ("installed", "title", "call"),
    [(False, "Set up a server here, as a service", ("_install", (False, {}))),
     (True, "Change the server running here", ("_edit", ({},)))],
)  # fmt: skip
def test_the_menu_sets_up_or_changes_the_server(
    typed: Typist, ran: Ran, monkeypatch: pytest.MonkeyPatch, installed: bool, title: str, call: tuple
) -> None:
    monkeypatch.setattr(menu, "find_manager", lambda: Manager(installed))
    typed(*[DOWN] * 4, ENTER)
    assert cli.main([]) == 7
    assert ran.calls == [call]
    assert typed.showed(f"? What do you want to do? {title}")


@pytest.mark.parametrize(
    ("installed", "last"),
    [(None, "See or end sessions on the server"), (False, "Set up a server here, as a service"),
     (True, "Change the server running here")],
)  # fmt: skip
def test_the_menu_offers_a_server_only_where_services_are_supported(
    monkeypatch: pytest.MonkeyPatch, installed: bool | None, last: str
) -> None:
    offered: list[dict[str, str]] = []

    def choose(question: str, choices: dict, default: object) -> object:
        offered.append(choices)
        assert (question, default) == ("What do you want to do?", menu._tunnel)
        return menu._login

    monkeypatch.setattr(menu, "find_manager", lambda: Manager(installed))
    monkeypatch.setattr(ask, "choose", choose)
    monkeypatch.setattr(client_cli, "_login", lambda *args: 3)
    assert menu.run() == 3
    [choices] = offered
    assert list(choices.values())[:4] == [
        "Open a tunnel",
        "Log in to a server",
        "Mint a token for someone",
        "See or end sessions on the server",
    ]
    assert list(choices.values())[-1] == last
    assert len(choices) == 4 + (installed is not None)


def test_kick_lists_a_session_id_among_the_readings(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    server.listed = [ALICE, BOB | {"names": [ALICE["id"]]}]
    assert cli.main(["kick", ALICE["id"]]) == 2
    assert capsys.readouterr().err.splitlines()[:3] == [
        f"{ALICE['id']} names different sessions:",
        f"  as session: {ALICE['id']}",
        f"  as name: {BOB['id']}",
    ]


def test_kick_in_a_terminal_asks_the_server_given(typed: Typist, logged_in: ClientConfig, server: Server) -> None:
    server.listed = [ALICE]
    typed("y", ENTER)
    assert cli.main(["kick", "--server", "other.example.com"]) == 1
    assert [config.server for config, _targets, _ask in server.asked] == ["other.example.com"] * 2


@pytest.mark.parametrize(
    ("reach", "answer", "err"),
    [
        ({"admin": True, "see": "all", "kick": "own"}, {"sessions": [], "refused": ["b2"]},
         ["not allowed to end b2", "this server keeps admins to their own sessions: WILDBURROW_KICK=own"]),
        ({"admin": True, "see": "own", "kick": "own"}, {"sessions": [], "refused": []},
         ["no session you can see matches", "this server keeps admins to their own sessions: WILDBURROW_SEE=own"]),
        ({"admin": False, "see": "own", "kick": "own"}, {"sessions": [], "refused": ["b2"]}, ["not allowed to end b2"]),
        ({"admin": True, "see": "all", "kick": "none"}, {"sessions": [], "refused": ["b2"]},
         ["not allowed to end b2", "this server keeps admins to their own sessions: WILDBURROW_KICK=none"]),
        ({"admin": True, "see": "admins", "kick": "admins"}, {"sessions": [], "refused": []},
         ["no session you can see matches"]),
    ],
)  # fmt: skip
def test_kick_says_when_the_server_keeps_admins_to_their_own(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], reach: dict, answer: dict, err: list
) -> None:
    server.reach, server.answer = reach, answer
    assert cli.main(["kick", "--who", "x"]) == 1
    assert capsys.readouterr().err.splitlines() == err
