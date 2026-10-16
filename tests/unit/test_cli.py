import builtins
import dataclasses
import logging
import re
import runpy
import stat
import sys
import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from wildburrow import __main__ as cli
from wildburrow.auth.token import digest
from wildburrow.client.config import ClientConfig, config_path, read_config, write_config
from wildburrow.client.ssh import KEEPALIVE, ssh_command
from wildburrow.config import PREFIX


@pytest.fixture(autouse=True)
def config_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def execs(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(config: ClientConfig, port: int, names: list[str], local_host: str) -> int:
        calls.append(ssh_command(config, port, names, local_host))
        return 0

    monkeypatch.setattr(cli.ssh, "run", run)
    return calls


def test_config_path_defaults_to_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert config_path() == tmp_path / ".config" / "wildburrow" / "config.toml"


text = st.text(st.characters(exclude_categories=["Cs"]))


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(text, st.integers(1, 65535), text)
def test_config_round_trip(server: str, port: int, user: str) -> None:
    path = config_path()
    write_config(path, ClientConfig(server, port, user))
    assert read_config(path) == ClientConfig(server, port, user)


def test_unknown_config_keys_are_ignored() -> None:
    path = config_path()
    path.parent.mkdir(parents=True)
    path.write_text('server = "s"\nfuture = true\n')
    assert read_config(path) == ClientConfig("s")


def test_missing_config() -> None:
    assert read_config(config_path()) is None


def test_username_falls_back_to_the_local_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "local")
    assert ClientConfig("s").username == "local"
    assert ClientConfig("s", user="set").username == "set"


def test_ssh_command() -> None:
    command = ssh_command(ClientConfig("tunnel.example.com", 2200, "me"), 3000, ["*.foo", "app"], "localhost")
    assert command[:2] == ["ssh", "-T"]
    assert command[4:6] == list(KEEPALIVE)
    assert command[command.index("-p") + 1] == "2200"
    assert [command[i + 1] for i, arg in enumerate(command) if arg == "-R"] == [
        "*.foo:80:localhost:3000",
        "app:80:localhost:3000",
    ]
    assert command[-2:] == ["--", "me@tunnel.example.com"]


def test_port_and_names_default_to_connect(execs: list[list[str]]) -> None:
    assert cli.main(["login", "tunnel.example.com", "--user", "me"]) == 0
    cli.main(["3000", "*.foo"])
    assert execs == [ssh_command(ClientConfig("tunnel.example.com", 2222, "me"), 3000, ["*.foo"], "localhost")]


def test_flags_override_saved_config(execs: list[list[str]]) -> None:
    cli.main(["login", "saved.example.com", "--ssh-port", "1", "--user", "saved"])
    cli.main(["connect", "8000", "a", "--server", "other.example.com", "--ssh-port", "2", "--local-host", "127.0.0.1"])
    expected = ssh_command(ClientConfig("other.example.com", 2, "saved"), 8000, ["a"], "127.0.0.1")
    assert execs == [expected]


def test_connect_without_saved_config(execs: list[list[str]], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "local")
    cli.main(["3000", "a", "--server", "s.example.com", "--user", "u"])
    assert execs[0][-1] == "u@s.example.com"


def test_connect_needs_a_server(capsys: pytest.CaptureFixture[str], execs: list[list[str]]) -> None:
    assert cli.main(["3000", "a"]) == 2
    assert capsys.readouterr().err == "no server configured: run `wildburrow login <server>` or pass --server\n"
    assert execs == []


def test_login_writes_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["login", "s.example.com"]) == 0
    assert tomllib.loads(config_path().read_text()) == dataclasses.asdict(ClientConfig("s.example.com"))
    assert config_path().stat().st_mode & 0o777 == 0o600
    assert str(config_path()) in capsys.readouterr().out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert capsys.readouterr().out.strip() == version("wildburrow")


def block_import(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == module:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


@pytest.mark.parametrize(("command", "module"), [("serve", "wildburrow.server"), ("hash-password", "argon2")])
def test_server_commands_need_the_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], command: str, module: str
) -> None:
    block_import(monkeypatch, module)
    assert cli.main([command]) == 2
    assert capsys.readouterr().err.strip() == cli.SERVER_EXTRA


def test_hash_password(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "pw")
    assert cli.main(["hash-password"]) == 0
    assert PasswordHasher().verify(capsys.readouterr().out.strip(), "pw")
    assert prompts == ["password: ", "again: "]


def test_hash_password_mismatch(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    answers = iter(["one", "two"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(answers))
    assert cli.main(["hash-password"]) == 1
    assert capsys.readouterr().err == "passwords do not match\n"


def test_serve_runs_the_server(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}

    async def fake_serve(env):
        seen["env"] = env

    monkeypatch.setattr("wildburrow.server.serve", fake_serve)
    assert cli.main(["serve"]) == 0
    assert seen["env"] is cli.os.environ


def test_argv_defaults_to_sys_argv(monkeypatch: pytest.MonkeyPatch, execs: list[list[str]]) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["wildburrow", "3000", "a", "--server", "s"])
    cli.main()
    assert execs


def test_runs_as_a_module(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["wildburrow", "login", "s.example.com"])
    monkeypatch.delitem(sys.modules, "wildburrow.__main__")
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("wildburrow", run_name="__main__")
    assert exit_info.value.code == 0
    assert read_config(config_path()) == ClientConfig("s.example.com")


def test_serve_reports_configuration_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli.os, "environ", {})
    assert cli.main(["serve"]) == 2
    assert capsys.readouterr().err.startswith(f"configuration error: missing required setting(s): {PREFIX}DOMAIN")


def test_login_saves_every_option() -> None:
    args = ["login", "s", "--ssh-port", "1", "--user", "u", "--transport", "websocket", "--auth", "token"]
    args += ["--identity", "~/k", "--token", "t", "--url", "https://x"]
    args += ["--no-reconnect", "--retry-delay", "0.5", "--retry-max", "10"]
    assert cli.main(args) == 0
    assert read_config(config_path()) == ClientConfig(
        "s", 1, "u", "websocket", "token", "~/k", "t", "https://x", reconnect=False, retry_delay=0.5, retry_max=10
    )


def test_reconnect_flags_override_saved_config(monkeypatch: pytest.MonkeyPatch) -> None:
    configs: list[ClientConfig] = []
    monkeypatch.setattr(cli.ssh, "run", lambda config, *args: configs.append(config) or 0)
    cli.main(["login", "s", "--no-reconnect", "--retry-max", "5"])
    cli.main(["3000", "a"])
    cli.main(["3000", "a", "--reconnect", "--retry-delay", "2"])
    assert [(c.reconnect, c.retry_delay, c.retry_max) for c in configs] == [(False, 1.0, 5.0), (True, 2.0, 5.0)]


@pytest.mark.parametrize("value", ["0", "-1", "soon", "nan", "inf"])
def test_retry_seconds_must_be_positive(value: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["3000", "a", "--server", "s", "--retry-delay", value])
    assert exit_info.value.code == 2
    assert "--retry-delay: expected a" in capsys.readouterr().err


def test_websocket_transport_runs_the_websocket_client(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(cli.websocket, "run", lambda *args: calls.append(args) or 7)
    monkeypatch.setenv(cli.TOKEN_ENV, "from-env")
    cli.main(["login", "s", "--transport", "websocket", "--auth", "token", "--token", "saved"])
    assert cli.main(["3000", "a", "b", "--url", "http://override"]) == 7
    expected = ClientConfig("s", transport="websocket", auth="token", token="from-env", url="http://override")
    assert calls == [(expected, 3000, ["a", "b"], "localhost")]


def test_token_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["token", "ci"]) == 0
    token_line, server_line = capsys.readouterr().out.splitlines()
    token = token_line.rsplit(" ", 1)[1]
    assert server_line.endswith(f"ci:{digest(token)}")
    assert f"{PREFIX}AUTH_TOKEN_HASHES" in server_line


def test_serve_logs_with_timestamps(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(logging.root, "handlers", [])
    monkeypatch.setattr(logging.root, "level", logging.WARNING)

    async def fake_serve(env) -> None:
        logging.getLogger("wildburrow.test").info("hello")

    monkeypatch.setattr("wildburrow.server.serve", fake_serve)
    assert cli.main(["serve"]) == 0
    assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} INFO wildburrow.test hello\n", capsys.readouterr().err)


def test_config_is_private_from_the_start(monkeypatch: pytest.MonkeyPatch, config_home: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home / "missing" / "config"))
    modes: list[int] = []
    monkeypatch.setattr(Path, "chmod", lambda self, mode: modes.append(stat.S_IMODE(self.stat().st_mode)))
    assert cli.main(["login", "s", "--token", "secret"]) == 0
    assert modes == [0o600]
    assert stat.S_IMODE(config_path().parent.stat().st_mode) == 0o700


@pytest.mark.parametrize("option", ["--transport", "--auth"])
def test_unknown_choices_are_refused(option: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["3000", "a", "--server", "s", option, "pigeon"])
    assert exit_info.value.code == 2
    assert f"{option}: invalid choice: 'pigeon'" in capsys.readouterr().err


HELP = Path(__file__).parent / "help"


@pytest.mark.parametrize("page", sorted({*cli.COMMANDS, "wildburrow"}))
def test_help(page: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setenv("PYTHON_COLORS", "0")
    with pytest.raises(SystemExit):
        cli.main([*([] if page == "wildburrow" else [page]), "--help"])
    assert capsys.readouterr().out == (HELP / f"{page}.txt").read_text()


def test_connect_keeps_every_saved_option(monkeypatch: pytest.MonkeyPatch) -> None:
    configs: list[ClientConfig] = []
    monkeypatch.setattr(cli.websocket, "run", lambda config, *args: configs.append(config) or 0)
    args = ["login", "s", "--ssh-port", "1", "--user", "u", "--transport", "websocket", "--auth", "token"]
    args += ["--identity", "~/k", "--token", "t", "--url", "https://x"]
    args += ["--no-reconnect", "--retry-delay", "0.5", "--retry-max", "10"]
    cli.main(args)
    cli.main(["3000", "a"])
    assert configs == [read_config(config_path())]


def test_a_command_is_required(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main([])
    assert exit_info.value.code == 2
    assert capsys.readouterr().err.endswith("error: the following arguments are required: command\n")
