from pathlib import Path
from typing import Any

import pytest

from wildburrow import cli
from wildburrow.cli import users
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, read_config, write_config

NOW = 1_800_000_000
CAROL = {"name": "carol", "alias": "c", "source": "database", "admin": True, "password": True, "keys": ["phone"],
         "invited_until": None, "gone": False}  # fmt: skip
SERVER = ClientConfig("s.example.com", transport="websocket", auth="key")


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Logins and settings saved here, never in the real home."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


class Server:
    """What each command asked the server, answered with what the test set for it."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.answers: dict[str, dict[str, Any]] = {}

    def answering(self, name: str) -> Any:
        async def call(config: ClientConfig, *args: Any) -> dict[str, Any]:
            self.calls.append((name, config.server, *args[:-1]))
            return self.answers[name]

        return call


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Server:
    write_config(config_path(), SERVER)
    found = Server()
    for name in ("users", "invite", "set_admin", "remove_user"):
        monkeypatch.setattr(websocket, name, found.answering(name))
    return found


def test_users_are_listed_with_how_they_log_in(server: Server, capsys: pytest.CaptureFixture[str]) -> None:
    server.answers["users"] = {"users": [
        {**CAROL},
        {**CAROL, "name": "dave", "alias": None, "admin": False, "password": False, "keys": [],
         "invited_until": NOW},
        {**CAROL, "name": "erin", "alias": None, "source": "settings", "admin": False, "password": False, "keys": []},
        {**CAROL, "name": "gone", "source": "token", "gone": True},
    ], "memory": False}  # fmt: skip
    assert cli.main(["users"]) == 0
    assert capsys.readouterr().out == (
        "USER   ALIAS  FROM      ADMIN  LOGS IN WITH\n"
        "carol  c      invited   yes    password, key (phone)\n"
        "dave   -      invited   no     invited until 2027-01-15 08:00 UTC\n"
        "erin   -      settings  no     -\n"
        "gone   c      token     yes    removed\n"
    )
    assert server.calls == [("users", "s.example.com")]


def test_a_server_in_memory_is_warned_of(server: Server, capsys: pytest.CaptureFixture[str]) -> None:
    server.answers["users"] = {"users": [], "memory": True}
    assert cli.main(["users"]) == 0
    assert capsys.readouterr().err == users.MEMORY + "\n"


def test_a_refusal_is_said(server: Server, capsys: pytest.CaptureFixture[str]) -> None:
    server.answers["users"] = {"error": "only an admin can list users"}
    assert cli.main(["users"]) == 1
    assert capsys.readouterr().err == "only an admin can list users\n"


def test_an_invite_prints_what_to_run(server: Server, capsys: pytest.CaptureFixture[str]) -> None:
    server.answers["invite"] = {"name": "carol", "code": "wbi_x", "expires": NOW, "memory": False}
    assert cli.main(["users", "invite", "carol", "--expires", "1h"]) == 0
    assert capsys.readouterr().out == (
        "invited carol, until 2027-01-15 08:00 UTC; they run:\n  wildburrow join s.example.com wbi_x\n"
    )
    assert server.calls == [("invite", "s.example.com", "carol", 3600)]
    assert cli.main(["users", "--server", "other.example.com", "invite", "dave"]) == 0
    assert server.calls[-1] == ("invite", "other.example.com", "dave", 7 * 86400)


@pytest.mark.parametrize(
    ("args", "found", "out"),
    [
        (["promote"], {"changed": True, "still": False}, "carol is an admin\n"),
        (["promote"], {"changed": False, "still": False}, "carol was already an admin\n"),
        (["demote"], {"changed": True, "still": False}, "carol is not an admin\n"),
        (["demote"], {"changed": False, "still": True},
         "carol was already not an admin\ncarol is still an admin by the server's WILDBURROW_ADMINS, which only its "
         "settings change\n"),
    ],
)  # fmt: skip
def test_admins_are_made_and_unmade(
    server: Server, capsys: pytest.CaptureFixture[str], args: list[str], found: dict, out: str
) -> None:
    server.answers["set_admin"] = found
    assert cli.main(["users", *args, "carol"]) == 0
    assert capsys.readouterr().out == out
    assert server.calls == [("set_admin", "s.example.com", "carol", args == ["promote"])]


@pytest.mark.parametrize(
    ("ended", "out"), [([], "removed carol\n"), (["s1"], "removed carol\nended 1 of their sessions\n")]
)
def test_a_user_is_removed(server: Server, capsys: pytest.CaptureFixture[str], ended: list, out: str) -> None:
    server.answers["remove_user"] = {"name": "carol", "ended": ended}
    assert cli.main(["users", "remove", "carol"]) == 0
    assert capsys.readouterr().out == out
    assert server.calls == [("remove_user", "s.example.com", "carol")]


@pytest.fixture
def prompts() -> list[str]:
    return []


@pytest.fixture
def joins(monkeypatch: pytest.MonkeyPatch, prompts: list[str]) -> list[tuple[ClientConfig, dict[str, Any]]]:
    sent: list[tuple[ClientConfig, dict[str, Any]]] = []

    async def join(config: ClientConfig, request: dict[str, Any]) -> str:
        sent.append((config, request))
        if request["code"] == "wbi_bad":
            raise websocket.ClientError("that invite can't be used: it was used, ended or ran out")
        return "carol"

    monkeypatch.setattr(websocket, "join", join)
    monkeypatch.setattr(users.getpass, "getpass", lambda prompt: prompts.append(prompt) or "pw")
    return sent


def test_joining_sets_a_password_and_saves_the_login(
    joins: list, prompts: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["join", "s.example.com", "wbi_x", "--alias", "c"]) == 0
    assert capsys.readouterr().out == f"joined s.example.com as carol; saved {config_path()}\n"
    assert prompts == ["password: ", "again: "]
    assert joins == [(ClientConfig("s.example.com", transport="websocket"),
                      {"code": "wbi_x", "alias": "c", "password": "pw"})]  # fmt: skip
    assert read_config(config_path()) == ClientConfig(
        "s.example.com", user="carol", transport="websocket", auth="password"
    )


def test_joining_with_a_key_alone(joins: list, tmp_path: Path) -> None:
    key = tmp_path / "my.key"
    (tmp_path / "my.key.pub").write_text("ssh-ed25519 AAAA me@laptop\n")
    assert cli.main(["join", "s.example.com", "wbi_x", "--no-password", "--key", str(key), "--device", "phone"]) == 0
    assert joins[0][1] == {"code": "wbi_x", "public_key": "ssh-ed25519 AAAA me@laptop", "label": "phone"}
    assert read_config(config_path()) == ClientConfig(
        "s.example.com", user="carol", transport="websocket", auth="key", identity=str(key)
    )


@pytest.mark.parametrize(
    ("args", "code", "err"),
    [
        (["--no-password"], 2, "joining sets a password, a key, or both: drop --no-password, or pass --key\n"),
        (["--key", "/nowhere/key"], 1, "can't read /nowhere/key.pub: No such file or directory\n"),
    ],
)
def test_joining_that_cant_work(
    joins: list, capsys: pytest.CaptureFixture[str], args: list, code: int, err: str
) -> None:
    assert cli.main(["join", "s.example.com", "wbi_x", *args]) == code
    assert capsys.readouterr().err == err
    assert joins == []


def test_a_join_the_server_refuses_saves_nothing(joins: list, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["join", "s.example.com", "wbi_bad"]) == 1
    assert capsys.readouterr().err == "that invite can't be used: it was used, ended or ran out\n"
    assert read_config(config_path()) is None


def test_mismatched_passwords_join_nothing(
    joins: list, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter(["one", "two"])
    monkeypatch.setattr(users.getpass, "getpass", lambda prompt: next(answers))
    assert cli.main(["join", "s.example.com", "wbi_x"]) == 1
    assert capsys.readouterr().err == "passwords do not match\n"
    assert joins == []


def test_a_key_joined_with_and_no_device_is_named_by_its_comment(joins: list, tmp_path: Path) -> None:
    key = tmp_path / "id_ed25519"
    key.with_suffix(".pub").write_text("ssh-ed25519 AAAA me@laptop\n")
    assert cli.main(["join", "s.example.com", "wbi_x", "--key", str(key)]) == 0
    assert joins[0][1] == {"code": "wbi_x", "public_key": "ssh-ed25519 AAAA me@laptop", "password": "pw"}
    assert read_config(config_path()).auth == "password"  # type: ignore[union-attr]
