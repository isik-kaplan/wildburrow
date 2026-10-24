import time
from pathlib import Path
from typing import Any

import pytest

from tests.unit.conftest import ENTER, Typist
from tests.unit.test_cli_sessions import SERVER, Manager, Ran
from wildburrow import cli
from wildburrow.cli import client as client_cli
from wildburrow.cli import locking, menu
from wildburrow.cli.output import when
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, write_config
from wildburrow.client.locking import TYPED, LockRequest, new_secret
from wildburrow.locks import PASSWORD_BYTES

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
    for var in ("WILDBURROW_LOCK", "WILDBURROW_LOCK_FILE", "WILDBURROW_LINK", "WILDBURROW_LINK_EXPIRES"):
        monkeypatch.delenv(var, raising=False)


class Connected:
    """What a tunnel was started with."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[Any, ...]] = []
        monkeypatch.setattr(client_cli.websocket, "run", lambda *args: self.calls.append(args) or 0)

    @property
    def lock(self) -> LockRequest | None:
        [call] = self.calls
        return call[-1]


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
    assert run("--lock", "alice", "--lock") == 0
    lock = connected.lock
    assert lock is not None
    assert list(lock.users) == ["alice", "guest"]
    assert all(len(password) == len("x" * PASSWORD_BYTES) * 4 // 3 for password in lock.users.values())
    assert lock.users["alice"] != lock.users["guest"]
    assert lock.typed == frozenset()


def test_guests_are_numbered(connected: Connected, no_terminal: None) -> None:
    assert run("--lock", "--lock", "guest-2", "--lock", "--lock") == 0
    assert list(connected.lock.users) == ["guest", "guest-2", "guest-3", "guest-4"]


def test_a_second_guest_is_the_second(connected: Connected, no_terminal: None) -> None:
    assert run("--lock", "--lock") == 0
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
        (("--link", "3"), ["link-1", "link-2", "link-3"]),
        (("--link", " 2 "), ["link-1", "link-2"]),
        (("--link", "alice,bob", "--link"), ["alice", "bob", "link-1"]),
        (("--link", "link-4,", "--link", "1"), ["link-4", "link-5"]),
        (("--link", "2", "--link", "bob"), ["link-1", "link-2", "bob"]),
        (("--link", "0"), []),
    ],
)
def test_links_are_counted_or_labelled(connected: Connected, args: tuple[str, ...], labels: list[str]) -> None:
    assert run(*args) == 0
    assert [entry["label"] for entry in connected.lock.mint] == labels
    assert all(entry["expires"] is None for entry in connected.lock.mint)


def test_links_dont_take_a_username(connected: Connected, no_terminal: None) -> None:
    assert run("--lock", "link-1:x", "--link") == 0
    assert [entry["label"] for entry in connected.lock.mint] == ["link-2"]


def test_links_can_expire(connected: Connected, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 1000.5)
    assert run("--link", "--link-expires", "1h") == 0
    assert connected.lock.mint == [{"label": "link-1", "expires": 1000 + 3600}]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--lock", "a b:x"), "--lock: 'a b' can't be a username; use 1-64 letters, digits and . _ @ -"),
        (("--lock", "alice:x", "--lock", "alice:y"), "--lock: alice is given twice"),
        (("--link", "a b"), "--link: 'a b' can't label a link; use 1-64 letters, digits and . _ @ -"),
        (("--link", "a,a"), "--link: a is given twice"),
        (("--lock", "a:x", "--link", "a"), "--link: a is given twice"),
        (("--link", "--link-expires", "soon"), "--link-expires: expected a duration like 30m, 12h or 7d, got 'soon'"),
        (("--lock-path", "/x"), "lock settings need --lock or --link"),
        (("--link-expires", "1h"), "lock settings need --lock or --link"),
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
def test_lock_mistakes_stop_before_connecting(
    connected: Connected, capsys: pytest.CaptureFixture[str], args: tuple[str, ...], message: str
) -> None:
    assert run(*args) == 2
    assert capsys.readouterr().err == message + "\n"
    assert connected.calls == []


def test_lock_settings_come_from_options(connected: Connected, tmp_path: Path) -> None:
    page = tmp_path / "login.html"
    page.write_text("<p>$title</p>")
    args = ("--link", "--lock-path", "/.in", "--lock-cookie", "pass", "--lock-header", "X-In", "--lock-user-header",
            "X-Who", "--lock-expires", "2h", "--no-lock-confirm-links", "--lock-page", str(page))  # fmt: skip
    assert run(*args) == 0
    assert connected.lock.settings == {
        "path": "/.in", "cookie": "pass", "header": "X-In", "user_header": "X-Who", "expires": "2h",
        "confirm_links": False, "page": "<p>$title</p>",
    }  # fmt: skip


def test_the_environment_locks_too(connected: Connected, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    users = tmp_path / "users"
    users.write_text("alice:x\n\n  \nbob:y\n")
    monkeypatch.setenv("WILDBURROW_LOCK_FILE", str(users))
    monkeypatch.setenv("WILDBURROW_LINK", "carol,dave")
    monkeypatch.setenv("WILDBURROW_LINK_EXPIRES", "1m")
    monkeypatch.setenv("WILDBURROW_LOCK_PATH", "/env")
    monkeypatch.setenv("WILDBURROW_LOCK_CONFIRM_LINKS", "no")
    monkeypatch.setenv("WILDBURROW_LOCK_PAGE", "<html>")
    assert run("--lock-path", "/flag") == 0
    lock = connected.lock
    assert lock.users == {"alice": "x", "bob": "y"}
    assert [entry["label"] for entry in lock.mint] == ["carol", "dave"]
    assert all(entry["expires"] > time.time() for entry in lock.mint)
    assert lock.settings == {"path": "/flag", "confirm_links": False, "page": "<html>"}


def test_options_win_over_the_environment(connected: Connected, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WILDBURROW_LOCK", "alice:x")
    monkeypatch.setenv("WILDBURROW_LINK", "9")
    assert run("--lock", "bob:y", "--link", "carol") == 0
    assert (connected.lock.users, [entry["label"] for entry in connected.lock.mint]) == ({"bob": "y"}, ["carol"])


def test_a_lock_setting_the_environment_gets_wrong(
    connected: Connected, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("WILDBURROW_LOCK_CONFIRM_LINKS", "maybe")
    assert run("--link") == 2
    assert capsys.readouterr().err.startswith("WILDBURROW_LOCK_CONFIRM_LINKS: expected one of")


def test_ssh_tunnels_cant_be_locked(connected: Connected, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("--transport", "ssh", "--link") == 2
    assert capsys.readouterr().err == "--lock and --link need --transport websocket\n"


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
        "secret": lock.secret, "users": {"alice": "x"}, "links": {}, "ended": [], "mint": [{"label": "l"}],
        "settings": {"path": "/p"},
    }  # fmt: skip
    assert lock.secret != LockRequest({}).secret
    assert len(new_secret()) == 44


class Logins:
    """What `link` and `links` are answered with, and what they asked."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.asked: list[Any] = []
        self.servers: list[str] = []
        self.listed: list[dict[str, Any]] = []
        self.minted: dict[str, Any] = {"label": "link-1", "url": "http://u"}
        self.ended: dict[str, Any] = {"who": "bob", "ended": []}
        monkeypatch.setattr(websocket, "logins", self.logins)
        monkeypatch.setattr(websocket, "link", self.link)
        monkeypatch.setattr(websocket, "end_login", self.end_login)

    async def logins(self, config: ClientConfig, ask: object) -> list[dict[str, Any]]:
        self.servers.append(config.server)
        return self.listed

    async def link(self, config: ClientConfig, request: dict[str, Any], ask: object) -> dict[str, Any]:
        self.servers.append(config.server)
        self.asked.append(request)
        return self.minted

    async def end_login(self, config: ClientConfig, who: str, ask: object) -> dict[str, Any]:
        self.servers.append(config.server)
        self.asked.append(who)
        return self.ended


@pytest.fixture
def logins(monkeypatch: pytest.MonkeyPatch, logged_in: ClientConfig) -> Logins:
    return Logins(monkeypatch)


def test_link_mints_one_more(logins: Logins, capsys: pytest.CaptureFixture[str], monkeypatch) -> None:
    assert cli.main(["link", "https://a.foo/x"]) == 0
    assert capsys.readouterr().out == "link-1  http://u\n"
    monkeypatch.setattr(time, "time", lambda: 100.7)
    assert cli.main(["link", "foo", "--as", "bob", "--expires", "2m"]) == 0
    assert logins.asked == [{"url": "https://a.foo/x", "label": None}, {"url": "foo", "label": "bob", "expires": 220}]


def test_link_says_why_not(logins: Logins, capsys: pytest.CaptureFixture[str]) -> None:
    logins.minted = {"error": "no locked tunnel of yours serves 'x'"}
    assert cli.main(["link", "x"]) == 1
    assert capsys.readouterr().err == "no locked tunnel of yours serves 'x'\n"
    assert cli.main(["link", "x", "--expires", "later"]) == 2
    assert capsys.readouterr().err == "--expires: expected a duration like 30m, 12h or 7d, got 'later'\n"


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
                entry("bob", logins=1),
                entry("carol"),
                entry("dave", ended=True, logins=3),
                entry("link-1", "link", used=LATER, logins=1, seen=LATER),
                entry("link-2", "link"),
                entry("link-3", "link", expires=LATER),
                entry("link-4", "link", expires=1),
            ],
        },
        {"names": ["bar"], "logins": [entry("eve", "link")]},
    ]
    assert cli.main(["links"]) == 0
    used, until = f"used {when(LATER)}", f"unused, until {when(LATER)}"
    width = len(until)
    assert capsys.readouterr().out == (
        "foo, *.foo\n"
        f"WHO     KIND      {'USED'.ljust(width)}  LAST SEEN\n"
        f"alice   password  {'2 logins'.ljust(width)}  {when(LATER)}\n"
        f"bob     password  {'1 login'.ljust(width)}  -\n"
        f"carol   password  {'-'.ljust(width)}  -\n"
        f"dave    password  {'ended'.ljust(width)}  -\n"
        f"link-1  link      {used.ljust(width)}  {when(LATER)}\n"
        f"link-2  link      {'unused'.ljust(width)}  -\n"
        f"link-3  link      {until}  -\n"
        f"link-4  link      {'expired'.ljust(width)}  -\n"
        "\n"
        "bar\n"
        "WHO  KIND  USED    LAST SEEN\n"
        "eve  link  unused  -\n"
    )


def test_links_with_nothing_locked(logins: Logins, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["links"]) == 0
    assert capsys.readouterr().out == "no locked tunnels of yours\n"


def test_links_ends_one(logins: Logins, capsys: pytest.CaptureFixture[str]) -> None:
    logins.ended = {"who": "bob", "ended": [["foo", "*.foo"], ["bar"]]}
    assert cli.main(["links", "--end", "bob"]) == 0
    assert capsys.readouterr().out == "ended bob on foo, *.foo\nended bob on bar\n"
    logins.ended = {"who": "bob", "ended": []}
    assert cli.main(["links", "--end", "bob"]) == 1
    assert capsys.readouterr().err == "no password or link named bob in your locked tunnels\n"
    assert logins.asked == ["bob", "bob"]


def test_the_menu_can_lock_a_tunnel(typed: Typist, ran: Ran) -> None:
    typed(ENTER, "3000", ENTER, "app", ENTER, "y", "alice bob", ENTER, "2", ENTER)
    assert cli.main([]) == 7
    assert ran.calls == [("_connect", (3000, ("app",), None, "localhost", {"lock": ("alice", "bob"), "link": ("2",)}))]
    assert typed.showed(
        "? Lock it, so only people you let in see it? Yes",
        "? Usernames to give a password, separated by spaces (empty for none) alice bob",
        "? One-time links: how many, or labels separated by commas (empty for none) 2",
    )


@pytest.mark.parametrize(
    ("users", "links", "options"),
    [("", "", {"lock": ("",), "link": ()}), ("", "carol", {"lock": (), "link": ("carol",)})],
)
def test_the_menu_locks_with_whatever_is_given(
    typed: Typist,
    ran: Ran,
    users: str,
    links: str,
    options: dict[str, Any],
) -> None:
    typed(ENTER, "3000", ENTER, "app", ENTER, "y", users, ENTER, links, ENTER)
    assert cli.main([]) == 7
    assert ran.calls == [("_connect", (3000, ("app",), None, "localhost", options))]


def test_lock_options_are_all_known() -> None:
    assert {
        "lock", "link", "link_expires", "lock_path", "lock_cookie", "lock_header", "lock_user_header",
        "lock_expires", "lock_confirm_links", "lock_page", "lock_link_page", "lock_message_page",
    } == locking.NAMES  # fmt: skip
    assert SERVER


def test_the_login_commands_ask_the_server_given(logins: Logins) -> None:
    assert cli.main(["link", "x", "--server", "other"]) == 0
    assert cli.main(["links", "--server", "other"]) == 0
    logins.ended = {"who": "bob", "ended": [["foo"]]}
    assert cli.main(["links", "--end", "bob", "--server", "other"]) == 0
    assert cli.main(["links"]) == 0
    assert logins.servers == ["other", "other", "other", SERVER]


def test_a_link_expires_at_its_expiry(logins: Logins, capsys: pytest.CaptureFixture[str], monkeypatch) -> None:
    logins.listed = [{"names": ["foo"], "logins": [entry("l", "link", expires=LATER)]}]
    monkeypatch.setattr(time, "time", lambda: LATER)
    assert cli.main(["links"]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "l    link  expired  -"
