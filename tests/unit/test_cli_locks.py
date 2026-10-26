import dataclasses
import re
import time
from pathlib import Path
from typing import Any

import click
import pytest
from isik.common.settings import UNSET

from tests.unit.conftest import ENTER, Typist
from tests.unit.test_cli_sessions import SERVER, Manager, Ran
from wildburrow import cli
from wildburrow.cli import client as client_cli
from wildburrow.cli import locking, menu
from wildburrow.cli.output import when
from wildburrow.cli.settings import Tunnel
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, write_config
from wildburrow.client.locking import TYPED, LockRequest, new_secret
from wildburrow.locks import FIELDS, PASSWORD_BYTES

LATER = 2_000_000_000


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


@pytest.fixture
def ran(monkeypatch: pytest.MonkeyPatch) -> Ran:
    monkeypatch.setattr(menu, "find_manager", lambda: Manager(False))
    return Ran(monkeypatch)


@pytest.fixture(autouse=True)
def quiet_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "WILDBURROW_CLIENT_LOCK",
        "WILDBURROW_CLIENT_LOCK_FILE",
        "WILDBURROW_CLIENT_LINK",
        "WILDBURROW_CLIENT_LINKS",
        "WILDBURROW_CLIENT_LINK_EXPIRES",
    ):
        monkeypatch.delenv(var, raising=False)


class Connected:
    """What a tunnel was started with."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[Any, ...]] = []
        monkeypatch.setattr(client_cli.websocket, "run", lambda *args: self.calls.append(args) or 0)

    @property
    def lock(self) -> LockRequest | None:
        [call] = self.calls
        return call[5]


@pytest.fixture
def connected(monkeypatch: pytest.MonkeyPatch, logged_in: ClientConfig) -> Connected:
    return Connected(monkeypatch)


def run(*args: str) -> int:
    return cli.main(["3000", "app", *args])


def test_no_lock_unless_asked(connected: Connected) -> None:
    assert run() == 0
    assert connected.lock is None


def test_given_passwords_are_kept(connected: Connected, no_terminal: None) -> None:
    assert run("--lock", "alice:wonder:land", "--lock", "bob:baz") == 0
    lock = connected.lock
    assert lock is not None
    assert (lock.users, lock.typed, lock.mint, lock.settings) == (
        {"alice": "wonder:land", "bob": "baz"}, frozenset(), [], {},
    )  # fmt: skip


def test_passwords_are_made_up_without_a_terminal(connected: Connected, no_terminal: None) -> None:
    assert run("--lock", "alice", "--lock-guest") == 0
    lock = connected.lock
    assert lock is not None
    assert list(lock.users) == ["alice", "guest"]
    assert all(len(password) == len("x" * PASSWORD_BYTES) * 4 // 3 for password in lock.users.values())
    assert lock.users["alice"] != lock.users["guest"]
    assert lock.typed == frozenset()


def test_guests_are_numbered(connected: Connected, no_terminal: None) -> None:
    assert run("--lock-guest", "--lock", "guest", "--lock", "guest-2", "--lock", "") == 0
    assert list(connected.lock.users) == ["guest", "guest-2", "guest-3", "guest-4"]


def test_a_second_guest_is_the_second(connected: Connected, no_terminal: None) -> None:
    assert run("--lock", "guest", "--lock-guest") == 0
    assert list(connected.lock.users) == ["guest", "guest-2"]


def test_typed_passwords_are_not_printed_back(connected: Connected, typed: Typist) -> None:
    typed("secret", ENTER, ENTER)
    assert run("--lock", "alice", "--lock", "bob") == 0
    lock = connected.lock
    assert lock.users["alice"] == "secret"
    assert len(lock.users["bob"]) == 16
    assert lock.typed == frozenset({"alice"})
    assert typed.showed("? Password for alice (empty makes one up) ******", "? Password for bob (empty makes one up)")


@pytest.mark.parametrize(
    ("args", "labels"),
    [
        (("--link",), ["link-1"]),
        (("--links", "3"), ["link-1", "link-2", "link-3"]),
        (("--links", " 2 "), ["link-1", "link-2"]),
        (("--links", "alice,bob", "--link"), ["alice", "bob", "link-1"]),
        (("--link", "--links", "alice,bob"), ["alice", "bob", "link-1"]),
        (("--links", "link-4,", "--links", "1"), ["link-4", "link-5"]),
        (("--links", "2", "--links", "bob"), ["link-1", "link-2", "bob"]),
        (("--links", "0"), []),
    ],
)
def test_links_are_counted_or_labelled(connected: Connected, args: tuple[str, ...], labels: list[str]) -> None:
    assert run(*args) == 0
    assert [entry["label"] for entry in connected.lock.mint] == labels
    assert all(entry["expires"] is None for entry in connected.lock.mint)


def test_a_link_may_share_a_passwords_name(connected: Connected, no_terminal: None) -> None:
    assert run("--lock", "link-1:x", "--lock", "anil:y", "--link", "--links", "anil") == 0
    assert [entry["label"] for entry in connected.lock.mint] == ["anil", "link-1"]


@pytest.mark.parametrize(
    ("given", "uses"),
    [((), 1), (("--link-uses", "1"), 1), (("--link-uses", "3"), 3), (("--link-uses", " ANY "), None)],
)
def test_links_work_as_often_as_asked(connected: Connected, given: tuple[str, ...], uses: int | None) -> None:
    assert run("--links", "2", *given) == 0
    assert [entry["uses"] for entry in connected.lock.mint] == [uses, uses]


@pytest.mark.parametrize("uses", ["0", "-1", "many"])
def test_a_link_works_at_least_once(connected: Connected, capsys: pytest.CaptureFixture[str], uses: str) -> None:
    assert run("--link", "--link-uses", uses) == 2
    assert capsys.readouterr().err.splitlines()[-1].endswith("expected a number from 1, or any")


def test_links_can_expire(connected: Connected, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 1000.5)
    assert run("--link", "--link-expires", "1h") == 0
    assert connected.lock.mint == [{"label": "link-1", "expires": 1000 + 3600, "uses": 1}]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--lock", "a b:x"), "--lock: 'a b' can't be a username; use 1-64 letters, digits and . _ @ -"),
        (("--lock", "alice:x", "--lock", "alice:y"), "--lock: alice is given twice"),
        (("--links", "a b"), "--links: 'a b' can't label a link; use 1-64 letters, digits and . _ @ -"),
        (("--links", "a,a"), "--links: a is given twice"),
    ],
)
def test_lock_mistakes_stop_before_connecting(
    connected: Connected, capsys: pytest.CaptureFixture[str], args: tuple[str, ...], message: str
) -> None:
    assert run(*args) == 2
    assert capsys.readouterr().err == message + "\n"
    assert connected.calls == []


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (
            ("--link", "--link-expires", "soon"),
            "Invalid value for '--link-expires': expected a duration like 30m, 12h or 7d",
        ),
        (("--lock-path", "/x"), "lock settings need --lock, --lock-guest, --link or --links"),
        (("--link-expires", "1h"), "lock settings need --lock, --lock-guest, --link or --links"),
        (("--link", "--lock-path", "x"), "--lock-path: expected a path like /_wildburrow/login, got 'x'"),
        (
            ("--link", "--lock-header", "X-A", "--lock-user-header", "x-a"),
            "--lock-header and --lock-user-header must differ",
        ),
        (
            ("--link", "--lock-path", "x", "--lock-cookie", " "),
            "--lock-path: expected a path like /_wildburrow/login, got 'x'; --lock-cookie: ' ' can't be a cookie name",
        ),
    ],
)
def test_lock_settings_that_cant_be_are_usage_errors(
    connected: Connected, capsys: pytest.CaptureFixture[str], args: tuple[str, ...], message: str
) -> None:
    assert run(*args) == 2
    # click refuses a value its own type can't take; the settings' own checks answer with just the message.
    assert capsys.readouterr().err.splitlines()[-1].removeprefix("Error: ") == message
    assert connected.calls == []


def test_lock_settings_come_from_options(connected: Connected, tmp_path: Path) -> None:
    page = tmp_path / "login.html"
    page.write_text("<p>$title</p>")
    args = ("--link", "--lock-path", "/.in", "--lock-cookie", "pass", "--lock-header", "X-In", "--lock-user-header",
            "X-Who", "--lock-expires", "2h", "--no-lock-confirm-links", "--lock-page-file", str(page))  # fmt: skip
    assert run(*args) == 0
    assert connected.lock.settings == {
        "path": "/.in", "cookie": "pass", "header": "X-In", "user_header": "X-Who", "expires": "2h",
        "confirm_links": False, "page": "<p>$title</p>",
    }  # fmt: skip


def test_the_environment_locks_too(connected: Connected, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    users = tmp_path / "users"
    users.write_text("alice:x\n\n  \nbob:y\n")
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCK_FILE", str(users))
    monkeypatch.setenv("WILDBURROW_CLIENT_LINKS", "carol,dave")
    monkeypatch.setenv("WILDBURROW_CLIENT_LINK_EXPIRES", "1m")
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCK_PATH", "/env")
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCK_CONFIRM_LINKS", "no")
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCK_PAGE", "<html>")
    assert run("--lock-path", "/flag") == 0
    lock = connected.lock
    assert lock.users == {"alice": "x", "bob": "y"}
    assert [entry["label"] for entry in lock.mint] == ["carol", "dave"]
    assert all(entry["expires"] > time.time() for entry in lock.mint)
    assert lock.settings == {"path": "/flag", "confirm_links": False, "page": "<html>"}


def test_options_win_over_the_environment(connected: Connected, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCK", "alice:x")
    monkeypatch.setenv("WILDBURROW_CLIENT_LINKS", "9")
    assert run("--lock", "bob:y", "--links", "carol") == 0
    assert (connected.lock.users, [entry["label"] for entry in connected.lock.mint]) == ({"bob": "y"}, ["carol"])


def test_a_lock_setting_the_environment_gets_wrong(
    connected: Connected, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCK_CONFIRM_LINKS", "maybe")
    assert run("--link") == 2
    assert capsys.readouterr().err == (
        "WILDBURROW_CLIENT_LOCK_CONFIRM_LINKS: expected yes/no, true/false, on/off or 1/0, got 'maybe'\n"
    )


def test_ssh_tunnels_cant_be_locked(connected: Connected, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("--transport", "ssh", "--link") == 2
    assert capsys.readouterr().err == "a locked tunnel needs --transport websocket\n"


def test_an_open_ssh_tunnel_still_runs(connected: Connected, monkeypatch: pytest.MonkeyPatch) -> None:
    started = []
    monkeypatch.setattr(client_cli.ssh, "run", lambda *args, **kwargs: started.append(args) or 5)
    assert run("--transport", "ssh") == 5
    assert len(started) == 1


def test_a_lock_says_how_to_get_in_once() -> None:
    lines: list[str] = []
    lock = LockRequest({"alice": "x", "bobby": "y"}, frozenset({"alice"}), [{"label": "l", "expires": None}])
    state = {"links": {"l": {}}, "ended": []}
    lock.locked({"links": [{"label": "l", "url": "http://u"}], "state": state}, lines.append)
    assert lines == ["locked:", f"  alice  password: {TYPED}", "  bobby  password: y", "  l      http://u"]
    assert (lock.state, lock.mint) == (state, [])
    lock.locked({"links": [], "state": {"links": {}, "ended": ["alice"]}}, lines.append)
    assert len(lines) == 4
    assert lock.state == {"links": {}, "ended": ["alice"]}


def test_a_lock_sends_back_what_it_knows() -> None:
    lock = LockRequest({"alice": "x"}, mint=[{"label": "l"}], settings={"path": "/p"})
    assert lock.spec() == {
        "secret": lock.secret, "users": {"alice": "x"}, "links": {}, "ended": [], "counts": {},
        "mint": [{"label": "l"}], "settings": {"path": "/p"},
    }  # fmt: skip
    counted = {"links": {}, "ended": [], "counts": {"password:alice": {"logins": 2, "seen": 9}}}
    assert LockRequest({}, state=counted).spec()["counts"] == counted["counts"]
    assert lock.secret != LockRequest({}).secret
    assert len(new_secret()) == 44


class Logins:
    """What `link` and `links` are answered with, and what they asked."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.asked: list[Any] = []
        self.servers: list[str] = []
        self.configs: list[ClientConfig] = []
        self.listed: list[dict[str, Any]] = []
        self.minted: dict[str, Any] = {"label": "link-1", "url": "http://u"}
        self.ended: dict[str, Any] = {"who": "bob", "ended": []}
        monkeypatch.setattr(websocket, "logins", self.logins)
        monkeypatch.setattr(websocket, "link", self.link)
        monkeypatch.setattr(websocket, "end_logins", self.end_logins)

    async def logins(self, config: ClientConfig, ask: object) -> list[dict[str, Any]]:
        self.servers.append(config.server)
        return self.listed

    async def link(self, config: ClientConfig, request: dict[str, Any], ask: object) -> dict[str, Any]:
        self.servers.append(config.server)
        self.asked.append(request)
        return self.minted

    async def end_logins(self, config: ClientConfig, whos: list[str], ask: object) -> list[dict[str, Any]]:
        self.servers.append(config.server)
        self.configs.append(config)
        self.asked.append(list(whos))
        return [self.ended | {"who": who} for who in whos]


@pytest.fixture
def logins(monkeypatch: pytest.MonkeyPatch, logged_in: ClientConfig) -> Logins:
    return Logins(monkeypatch)


def test_link_mints_one_more(logins: Logins, capsys: pytest.CaptureFixture[str], monkeypatch) -> None:
    assert cli.main(["links", "add", "https://a.foo/x"]) == 0
    assert capsys.readouterr().out == "link-1  http://u\n"
    monkeypatch.setattr(time, "time", lambda: 100.7)
    assert cli.main(["links", "add", "foo", "--as", "bob", "--expires", "2m", "--uses", "any"]) == 0
    assert logins.asked == [
        {"url": "https://a.foo/x", "label": None, "uses": 1},
        {"url": "foo", "label": "bob", "expires": 220, "uses": None},
    ]


def test_link_says_why_not(logins: Logins, capsys: pytest.CaptureFixture[str]) -> None:
    logins.minted = {"error": "no locked tunnel of yours serves 'x'"}
    assert cli.main(["links", "add", "x"]) == 1
    assert capsys.readouterr().err == "no locked tunnel of yours serves 'x'\n"
    assert cli.main(["links", "add", "x", "--expires", "later"]) == 2
    assert capsys.readouterr().err.endswith(
        "Error: Invalid value for '--expires': expected a duration like 30m, 12h or 7d\n"
    )


def entry(who: str, kind: str = "password", **changes: Any) -> dict[str, Any]:
    return {
        "who": who,
        "kind": kind,
        "used": None,
        "logins": 0,
        "seen": None,
        "expires": None,
        "ended": False,
    } | changes


def test_links_lists_who_may_get_in(logins: Logins, capsys: pytest.CaptureFixture[str]) -> None:
    logins.listed = [
        {
            "names": ["foo", "*.foo"],
            "logins": [
                entry("alice", logins=2, seen=LATER),
                entry("dave", ended=True, logins=3),
                entry("alice", "link", used=LATER, spent=1, uses=1, logins=1, seen=LATER),
                entry("link-2", "link", spent=2, uses=5, expires=LATER),
                entry("link-3", "link", spent=4, uses=None),
                entry("link-4", "link", expires=1),
                # As a server before 0.5.0 lists a used link: when, and nothing on how often.
                entry("old", "link", used=LATER),
                entry("bob", used=LATER),
            ],
        },
        {"names": ["bar"], "logins": [entry("eve", "link")]},
    ]
    assert cli.main(["links"]) == 0
    first, second = capsys.readouterr().out.split("\n\n")
    header = ["WHO", "KIND", "STATE", "USES", "LOGINS", "LAST SEEN", "EXPIRES"]
    assert columns(first) == [
        ["foo, *.foo"], header,
        ["alice", "password", "open", "-", "2", when(LATER), "-"],
        ["dave", "password", "ended", "-", "3", "-", "-"],
        ["alice", "link", "used up", "1/1", "1", when(LATER), "-"],
        ["link-2", "link", "open", "2/5", "0", "-", when(LATER)],
        ["link-3", "link", "open", "4/any", "0", "-", "-"],
        ["link-4", "link", "expired", "0/1", "0", "-", when(1)],
        ["old", "link", "used up", "1/1", "0", "-", "-"],
        ["bob", "password", "open", "-", "0", "-", "-"],
    ]  # fmt: skip
    assert columns(second) == [["bar"], header, ["eve", "link", "open", "0/1", "0", "-", "-"]]


def columns(text: str) -> list[list[str]]:
    return [re.split(r"  +", line.strip()) for line in text.strip("\n").splitlines()]


def test_links_with_nothing_locked(logins: Logins, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["links"]) == 0
    assert capsys.readouterr().out == "no locked tunnels of yours\n"


def test_links_ends_one(logins: Logins, capsys: pytest.CaptureFixture[str]) -> None:
    logins.ended = {"who": "bob", "ended": [["foo", "*.foo"], ["bar"]]}
    assert cli.main(["links", "end", "bob"]) == 0
    assert capsys.readouterr().out == "ended bob on foo, *.foo\nended bob on bar\n"
    logins.ended = {"who": "bob", "ended": []}
    assert cli.main(["links", "end", "bob", "carol"]) == 1
    assert capsys.readouterr().err == "no password or link named bob, carol in your locked tunnels\n"
    assert logins.asked == [["bob"], ["bob", "carol"]]


def test_the_menu_can_lock_a_tunnel(typed: Typist, ran: Ran) -> None:
    typed(
        ENTER,
        "3000",
        ENTER,
        "app",
        ENTER,
        "y",
        "alice",
        ENTER,
        "bob",
        ENTER,
        ENTER,
        "2",
        ENTER,
        ENTER,
        ENTER,
        "\b",
        "4",
        ENTER,
        ENTER,
    )
    assert cli.main([]) == 7
    [(name, (port, names, settings))] = ran.calls
    assert (name, port, names) == ("_connect", 3000, ("app",))
    assert (settings.locked, settings.lock, settings.links, settings.link_expires, settings.link_uses) == (
        True,
        ("alice", "bob"),
        ("2",),
        UNSET,
        4,
    )
    assert typed.showed(
        "? Lock it, so only people you let in see it? Yes",
        "? Username to give a password, as USER or USER:PASSWORD (empty when done) alice",
        "? Username to give a password, as USER or USER:PASSWORD (empty when done) bob",
        "? One-time links: how many, or labels separated by commas (empty when done) 2",
        "? How long the links work, like 30m, 12h or 7d (empty for as long as the tunnel) [with the tunnel]",
        "? Change anything else, such as where the local port listens or how the lock works? No",
    )


def test_the_menu_can_change_how_the_lock_works(typed: Typist, ran: Ran) -> None:
    lock = ["/in", ENTER, ENTER, ENTER, ENTER, "1h", ENTER, "n"]
    typed(
        ENTER,
        "3000",
        ENTER,
        "app",
        ENTER,
        "y",
        ENTER,
        "carol",
        ENTER,
        ENTER,
        "2h",
        ENTER,
        ENTER,
        "y",
        "\b" * 9,
        "127.0.0.2",
        ENTER,
        *lock,
    )
    assert cli.main([]) == 7
    [(_name, (_port, _names, settings))] = ran.calls
    assert (settings.lock, settings.links, settings.link_expires, settings.local_host) == (
        (),
        ("carol",),
        "2h",
        "127.0.0.2",
    )
    assert settings.lock_settings() == {"path": "/in", "expires": "1h", "confirm_links": False}


@pytest.mark.parametrize(("links", "users"), [((), ["guest"]), (("carol",), [])])
def test_asking_for_a_lock_and_naming_no_one_makes_up_a_user(
    no_terminal: None, links: tuple[str, ...], users: list[str]
) -> None:
    lock = locking.request(Tunnel(locked=True, links=links))
    assert lock is not None
    assert list(lock.users) == users


def test_lock_options_are_every_lock_setting() -> None:
    names = {field.name for field in dataclasses.fields(Tunnel)}
    assert {name for name in names if name.startswith("lock_")} - {"lock_guest"} == {f"lock_{name}" for name in FIELDS}


def test_the_login_commands_ask_the_server_given(logins: Logins) -> None:
    assert cli.main(["links", "add", "x", "--server", "other"]) == 0
    assert cli.main(["links", "--server", "other"]) == 0
    logins.ended = {"who": "bob", "ended": [["foo"]]}
    assert cli.main(["links", "end", "bob", "--server", "other"]) == 0
    assert cli.main(["links", "--server", "other", "end", "bob"]) == 0
    assert cli.main(["links"]) == 0
    assert logins.servers == ["other", "other", "other", "other", SERVER]


def test_a_login_option_given_to_links_holds_for_its_command(logins: Logins) -> None:
    logins.ended = {"who": "bob", "ended": [["foo"]]}
    assert cli.main(["links", "--token", "t0k", "end", "bob"]) == 0
    assert (logins.configs[-1].auth, logins.configs[-1].token) == ("token", "t0k")


def test_a_link_expires_at_its_expiry(logins: Logins, capsys: pytest.CaptureFixture[str], monkeypatch) -> None:
    logins.listed = [{"names": ["foo"], "logins": [entry("l", "link", expires=LATER)]}]
    monkeypatch.setattr(time, "time", lambda: LATER)
    assert cli.main(["links"]) == 0
    assert columns(capsys.readouterr().out)[-1] == ["l", "link", "expired", "0/1", "0", "-", when(LATER)]


@pytest.mark.parametrize("args", [("--lock", "a:b"), ("--lock-guest",), ("--link",), ("--links", "2")])
def test_any_lock_option_takes_the_lock_settings(connected: Connected, args: tuple[str, ...]) -> None:
    assert run(*args, "--lock-path", "/in") == 0
    assert connected.lock.settings == {"path": "/in"}


def test_the_tunnel_goes_to_the_server_given(connected: Connected) -> None:
    assert run("--server", "other.example.com") == 0
    assert connected.calls[0][0].server == "other.example.com"


def test_the_menu_runs_connect_as_its_own_command(
    typed: Typist, connected: Connected, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    paths = []
    monkeypatch.setattr(client_cli, "_connect", lambda *args: paths.append(click.get_current_context().command_path))
    typed(ENTER, "3000", ENTER, "app", ENTER, ENTER, ENTER)
    assert cli.main([]) == 0
    assert paths == ["wildburrow connect"]


def test_the_menu_reports_a_lock_setting_that_cant_be(typed: Typist, connected: Connected, capsys) -> None:
    typed(ENTER, "3000", ENTER, "app", ENTER, "y", "alice:x", ENTER, ENTER, ENTER, "y", ENTER, "x", ENTER, *[ENTER] * 6)
    assert cli.main([]) == 2
    assert capsys.readouterr().err == "--lock-path: expected a path like /_wildburrow/login, got 'x'\n"


@pytest.mark.parametrize("flag", ["--index", "--no-index"])
def test_an_ssh_tunnel_takes_the_servers_indexing(
    connected: Connected, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    assert run("--transport", "ssh", flag) == 2
    assert capsys.readouterr().err == (
        "--index and --no-index need --transport websocket; an ssh tunnel takes the server's\n"
    )


@pytest.mark.parametrize(("args", "index"), [((), None), (("--index",), True), (("--no-index",), False)])
def test_the_tunnel_asks_what_it_was_told_about_search_engines(
    connected: Connected, args: tuple[str, ...], index: bool | None
) -> None:
    assert run(*args) == 0
    [call] = connected.calls
    assert call[6] is index
