import re

import pytest

from tests.unit import test_cli_locks as locks
from tests.unit.conftest import ENTER, Typist
from tests.unit.test_cli_locks import Connected, run
from wildburrow import cli
from wildburrow.cli import saved
from wildburrow.client.config import ClientConfig, config_path, read_config, read_toml, write_config, write_toml

home = locks.home
quiet_env = locks.quiet_env
logged_in = locks.logged_in
connected = locks.connected


@pytest.fixture(autouse=True)
def no_client_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    for entry in saved.SAVED.values():
        monkeypatch.delenv(entry.env_name, raising=False)


def rows(out: str) -> dict[str, tuple[str, str]]:
    found = {}
    for line in out.splitlines()[1:]:
        name, value, source = re.split(r"  +", line.strip())
        found[name] = (value, source)
    return found


def test_config_lists_every_setting_and_where_it_comes_from(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_config(config_path(), ClientConfig("s.example.com", token="secret"))
    write_toml(config_path(), {**read_toml(config_path()), "lock_path": "/in"})
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCAL_HOST", "127.0.0.2")
    assert cli.main(["config"]) == 0
    listed = rows(capsys.readouterr().out)
    assert set(listed) == set(saved.SAVED)
    assert listed["server"] == ("s.example.com", "config.toml")
    assert listed["token"] == ("(set)", "config.toml")
    assert listed["lock_path"] == ("/in", "config.toml")
    assert listed["local_host"] == ("127.0.0.2", "WILDBURROW_CLIENT_LOCAL_HOST")
    assert listed["lock_cookie"] == ("the server's", "default")
    assert listed["url"] == ("-", "config.toml")
    assert listed["lock_page"] == ("the server's", "default")
    assert listed["reconnect"] == ("true", "config.toml")


def test_config_lists_defaults_under_headings(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["config"]) == 0
    out = capsys.readouterr().out
    assert re.split(r"  +", out.splitlines()[0]) == ["NAME", "VALUE", "FROM"]
    listed = rows(out)
    assert listed["server"] == ("-", "default")
    assert listed["token"] == ("-", "default")
    assert listed["local_host"] == ("localhost", "default")


def test_config_set_saves_and_unset_forgets(capsys: pytest.CaptureFixture[str]) -> None:
    write_config(config_path(), ClientConfig("s.example.com"))
    assert cli.main(["config", "set", "local-host", "127.0.0.2"]) == 0
    assert capsys.readouterr().out == f"saved local_host in {config_path()}\n"
    assert cli.main(["config", "set", "ssh_port", "2200"]) == 0
    assert cli.main(["config", "set", "lock_confirm_links", "no"]) == 0
    saved_now = read_toml(config_path())
    assert (saved_now["local_host"], saved_now["ssh_port"], saved_now["lock_confirm_links"]) == (
        "127.0.0.2",
        2200,
        "no",
    )
    assert read_config(config_path()) == ClientConfig("s.example.com", ssh_port=2200)
    assert cli.main(["config", "unset", "local_host"]) == 0
    assert cli.main(["config", "unset", "local_host"]) == 0
    assert "local_host" not in read_toml(config_path())
    assert capsys.readouterr().out.splitlines()[-2:] == ["forgot local_host", "local_host isn't saved"]


def test_unsetting_the_last_setting_removes_the_file() -> None:
    assert cli.main(["config", "set", "local_host", "127.0.0.2"]) == 0
    assert read_config(config_path()) is None
    assert cli.main(["config", "unset", "local_host"]) == 0
    assert not config_path().exists()


@pytest.mark.parametrize(
    ("args", "error"),
    [
        (["set", "colour", "red"], "no client setting is called colour; `wildburrow config` lists them"),
        (["unset", "colour"], "no client setting is called colour; `wildburrow config` lists them"),
        (["set", "ssh_port", "lots"], "ssh_port: expected a whole number, got 'lots'"),
        (["set", "transport", "pigeon"], "transport: expected one of ssh, websocket, got 'pigeon'"),
    ],
)
def test_config_refuses_what_it_cant_save(args: list[str], error: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["config", *args]) == 2
    assert capsys.readouterr().err == f"{error}\n"
    assert not config_path().exists()


def test_an_option_beats_a_variable_beats_what_is_saved(connected: Connected, monkeypatch: pytest.MonkeyPatch) -> None:
    def local_host() -> str:
        return connected.calls.pop()[3]

    assert run() == 0
    assert local_host() == "localhost"
    assert cli.main(["config", "set", "local_host", "127.0.0.2"]) == 0
    assert run() == 0
    assert local_host() == "127.0.0.2"
    monkeypatch.setenv("WILDBURROW_CLIENT_LOCAL_HOST", "127.0.0.3")
    assert run() == 0
    assert local_host() == "127.0.0.3"
    assert run("--local-host", "127.0.0.4") == 0
    assert local_host() == "127.0.0.4"


def test_saved_lock_settings_apply_to_a_locked_tunnel(connected: Connected) -> None:
    assert cli.main(["config", "set", "lock_path", "/in"]) == 0
    assert run("--link") == 0
    assert connected.lock.settings == {"path": "/in"}


def test_a_saved_value_is_what_a_question_starts_from(typed: Typist, connected: Connected) -> None:
    assert cli.main(["config", "set", "local_host", "127.0.0.2"]) == 0
    typed("3000", ENTER, "app", ENTER, ENTER, "y", ENTER)
    assert cli.main(["connect"]) == 0
    assert connected.calls[0][3] == "127.0.0.2"
    assert typed.showed("? Where the local port listens 127.0.0.2")


def test_a_login_keeps_what_config_saved() -> None:
    assert cli.main(["config", "set", "local_host", "127.0.0.2"]) == 0
    write_config(config_path(), ClientConfig("s.example.com"))
    assert read_toml(config_path())["local_host"] == "127.0.0.2"
