import builtins
import dataclasses
import functools
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

from tests.unit.conftest import CTRL_C, DOWN, ENTER, Typist
from wildburrow import cli, plugins
from wildburrow.auth.token import digest
from wildburrow.cli import client as client_cli
from wildburrow.cli import server as server_cli
from wildburrow.client.config import ClientConfig, config_path, read_config, write_config
from wildburrow.client.ssh import KEEPALIVE, ssh_command
from wildburrow.config import PREFIX


@pytest.fixture(autouse=True)
def config_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


@pytest.fixture
def execs(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(config: ClientConfig, port: int, names: list[str], local_host: str) -> int:
        calls.append(ssh_command(config, port, names, local_host))
        return 0

    monkeypatch.setattr(client_cli.ssh, "run", run)
    return calls


def test_config_path_follows_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert config_path() == tmp_path / "xdg" / "wildburrow" / "config.toml"


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
    monkeypatch.setattr("getpass.getuser", lambda: "local")
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
    assert cli.main(["3000", "*.foo"]) == 0
    assert execs == [ssh_command(ClientConfig("tunnel.example.com", 2222, "me"), 3000, ["*.foo"], "localhost")]


def test_flags_override_saved_config(execs: list[list[str]]) -> None:
    cli.main(["login", "saved.example.com", "--ssh-port", "1", "--user", "saved"])
    cli.main(["connect", "8000", "a", "--server", "other.example.com", "--ssh-port", "2", "--local-host", "127.0.0.1"])
    expected = ssh_command(ClientConfig("other.example.com", 2, "saved"), 8000, ["a"], "127.0.0.1")
    assert execs == [expected]


def test_connect_without_saved_config(execs: list[list[str]], monkeypatch: pytest.MonkeyPatch) -> None:
    cli.main(["3000", "a", "--server", "s.example.com", "--user", "u"])
    assert execs[0][-1] == "u@s.example.com"


def test_connect_needs_a_server(capsys: pytest.CaptureFixture[str], execs: list[list[str]]) -> None:
    assert cli.main(["3000", "a"]) == 2
    assert capsys.readouterr().err == "no server configured: run `wildburrow login` or pass --server\n"
    assert execs == []


@pytest.mark.parametrize(
    ("args", "error"),
    [
        (["3000"], "Error: Missing argument 'NAME...'."),
        (["0", "a"], "Error: Invalid value for 'PORT': 0 is not in the range 1<=x<=65535."),
        (["3000", "a", "--transport", "pigeon"], "Error: Invalid value for '--transport': 'pigeon' is not one of"),
        (["3000", "a", "--auth", "pigeon"], "Error: Invalid value for '--auth': 'pigeon' is not one of"),
    ],
)
def test_bad_connect_arguments_are_usage_errors(
    args: list[str], error: str, capsys: pytest.CaptureFixture[str], execs: list[list[str]]
) -> None:
    assert cli.main(args) == 2
    assert capsys.readouterr().err.splitlines()[-1].startswith(error)
    assert execs == []


def test_login_writes_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["login", "s.example.com"]) == 0
    assert tomllib.loads(config_path().read_text()) == dataclasses.asdict(ClientConfig("s.example.com"))
    assert config_path().stat().st_mode & 0o777 == 0o600
    assert capsys.readouterr().out == f"saved {config_path()}\n"


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out == version("wildburrow") + "\n"


def block_import(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == module:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


@pytest.mark.parametrize(
    ("args", "module"),
    [(["serve"], "wildburrow.config"), (["service", "install"], "wildburrow.config"), (["hash-password"], "argon2")],
)
def test_server_commands_need_the_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], args: list[str], module: str
) -> None:
    block_import(monkeypatch, module)
    assert cli.main(args) == 2
    assert capsys.readouterr().err == server_cli.SERVER_EXTRA + "\n"


def test_hash_password(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(server_cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or "pw")
    assert cli.main(["hash-password"]) == 0
    assert PasswordHasher().verify(capsys.readouterr().out.strip(), "pw")
    assert prompts == ["password: ", "again: "]


def test_hash_password_mismatch(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    answers = iter(["one", "two"])
    monkeypatch.setattr(server_cli.getpass, "getpass", lambda prompt: next(answers))
    assert cli.main(["hash-password"]) == 1
    assert capsys.readouterr().err == "passwords do not match\n"


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    envs: list[dict[str, str]] = []

    async def fake_serve(env: dict[str, str]) -> None:
        envs.append(env)

    monkeypatch.setattr("wildburrow.server.serve", fake_serve)
    return envs


def test_serve_runs_the_server_with_the_environment(served: list[dict[str, str]]) -> None:
    assert cli.main(["serve"]) == 0
    assert served == [dict(server_cli.os.environ)]


def test_serve_options_replace_the_environment(served: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch) -> None:
    environ = {
        "HOME": "/home/u",
        f"{PREFIX}DOMAIN_FILE": "/run/domain",
        f"{PREFIX}HTTP_PORT": "80",
        f"{PREFIX}AUTH_KEY_AUTHORIZED_KEYS": "ssh-ed25519 AAAA",
        f"{PREFIX}DNS_MANAGE_RECORDS": "true",
        f"{PREFIX}ACME_EMAIL": "kept@example.com",
    }
    monkeypatch.setattr(server_cli.os, "environ", environ)
    args = ["serve", "--domain=tunnel.example.com", "--http-port", "8080", "--transports", "ssh,websocket"]
    args += ["--auth-key-authorized-keys-file", "/keys", "--no-dns-manage-records", "--https-proxy-protocol"]
    args += ["--dns-cloudflare-api-token", "cf", "--ssh-port", "22"]
    assert cli.main(args) == 0
    assert served == [
        {
            "HOME": "/home/u",
            f"{PREFIX}DOMAIN": "tunnel.example.com",
            f"{PREFIX}HTTP_PORT": "8080",
            f"{PREFIX}TRANSPORTS": "ssh,websocket",
            f"{PREFIX}AUTH_KEY_AUTHORIZED_KEYS_FILE": "/keys",
            f"{PREFIX}DNS_MANAGE_RECORDS": "off",
            f"{PREFIX}HTTPS_PROXY_PROTOCOL": "on",
            f"{PREFIX}DNS_CLOUDFLARE_API_TOKEN": "cf",
            f"{PREFIX}SSH_PORT": "22",
            f"{PREFIX}ACME_EMAIL": "kept@example.com",
        }
    ]
    assert environ[f"{PREFIX}HTTP_PORT"] == "80"


def test_serve_reads_an_env_file_between_the_environment_and_the_options(
    served: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(server_cli.os, "environ", {f"{PREFIX}DOMAIN": "env", f"{PREFIX}HTTP_PORT": "1"})
    path = tmp_path / "env"
    path.write_text(f'{PREFIX}HTTP_PORT="2"\n{PREFIX}SSH_PORT=3\n{PREFIX}DOMAIN_FILE=/d\n')
    assert cli.main(["serve", "--env-file", str(path), "--ssh-port", "4"]) == 0
    assert served == [{f"{PREFIX}HTTP_PORT": "2", f"{PREFIX}DOMAIN_FILE": "/d", f"{PREFIX}SSH_PORT": "4"}]


def test_serve_reports_a_bad_env_file(
    served: list[dict[str, str]], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = tmp_path / "env"
    path.write_text("no equals sign\n")
    assert cli.main(["serve", "--env-file", str(path)]) == 2
    assert capsys.readouterr().err == f"configuration error: {path}: line 1: expected KEY=VALUE\n"
    assert served == []


@pytest.mark.parametrize(
    ("args", "error"),
    [
        (["--domain", "a", "--domain-file", "b"], "Error: --domain and --domain-file can't be used together"),
        (["--dom", "a"], "Error: No such option '--dom'. (Did you mean one of: '--dns', '--domain'?)"),
    ],
)
def test_serve_refuses_ambiguous_options(
    served: list[dict[str, str]], capsys: pytest.CaptureFixture[str], args: list[str], error: str
) -> None:
    assert cli.main(["serve", *args]) == 2
    assert capsys.readouterr().err.splitlines()[-1] == error
    assert served == []


def test_serve_reports_what_it_could_not_start(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def fake_serve(env: dict[str, str]) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("wildburrow.server.serve", fake_serve)
    assert cli.main(["serve"]) == 1
    assert capsys.readouterr().err == "could not start: [Errno 13] Permission denied\n"


def test_argv_defaults_to_sys_argv(monkeypatch: pytest.MonkeyPatch, execs: list[list[str]]) -> None:
    monkeypatch.setattr(sys, "argv", ["wildburrow", "3000", "a", "--server", "s"])
    assert cli.main() == 0
    assert execs


def test_runs_as_a_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["wildburrow", "login", "s.example.com"])
    monkeypatch.delitem(sys.modules, "wildburrow.__main__", raising=False)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("wildburrow", run_name="__main__")
    assert exit_info.value.code == 0
    assert read_config(config_path()) == ClientConfig("s.example.com")


def test_serve_reports_configuration_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(server_cli.os, "environ", {})
    assert cli.main(["serve"]) == 2
    assert capsys.readouterr().err == f"configuration error: missing required setting(s): {PREFIX}DOMAIN\n"


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
    monkeypatch.setattr(client_cli.ssh, "run", lambda config, *args: configs.append(config) or 0)
    cli.main(["login", "s", "--no-reconnect", "--retry-max", "5"])
    cli.main(["3000", "a"])
    cli.main(["3000", "a", "--reconnect", "--retry-delay", "2"])
    assert [(c.reconnect, c.retry_delay, c.retry_max) for c in configs] == [(False, 1.0, 5.0), (True, 2.0, 5.0)]


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ("0", "expected a positive number of seconds, got '0'"),
        ("-1", "expected a positive number of seconds, got '-1'"),
        ("nan", "expected a positive number of seconds, got 'nan'"),
        ("inf", "expected a positive number of seconds, got 'inf'"),
        ("soon", "expected a number of seconds, got 'soon'"),
    ],
)
def test_retry_seconds_must_be_positive(value: str, error: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["3000", "a", "--server", "s", "--retry-delay", value]) == 2
    assert capsys.readouterr().err.splitlines()[-1] == f"Error: Invalid value for '--retry-delay': {error}"


def test_websocket_transport_runs_the_websocket_client(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(client_cli.websocket, "run", lambda *args: calls.append(args) or 7)
    monkeypatch.setenv(client_cli.TOKEN_ENV, "from-env")
    cli.main(["login", "s", "--transport", "websocket", "--auth", "token", "--token", "saved"])
    assert cli.main(["3000", "a", "b", "--url", "http://override"]) == 7
    expected = ClientConfig("s", transport="websocket", auth="token", token="from-env", url="http://override")
    assert calls == [(expected, 3000, ["a", "b"], "localhost")]


def test_token_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["token", "ci"]) == 0
    token_line, server_line = capsys.readouterr().out.splitlines()
    token = token_line.removeprefix("token (give this to the client): ")
    assert server_line == f"server line (add to {PREFIX}AUTH_TOKEN_HASHES): ci:{digest(token)}"


def test_serve_logs_with_timestamps(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(logging.root, "handlers", [])
    # Through setLevel, since loggers cache what an earlier level let through.
    request.addfinalizer(functools.partial(logging.root.setLevel, logging.root.level))
    logging.root.setLevel(logging.WARNING)

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


def test_connect_keeps_every_saved_option(monkeypatch: pytest.MonkeyPatch) -> None:
    configs: list[ClientConfig] = []
    monkeypatch.setattr(client_cli.websocket, "run", lambda config, *args: configs.append(config) or 0)
    args = ["login", "s", "--ssh-port", "1", "--user", "u", "--transport", "websocket", "--auth", "token"]
    args += ["--identity", "~/k", "--token", "t", "--url", "https://x"]
    args += ["--no-reconnect", "--retry-delay", "0.5", "--retry-max", "10"]
    cli.main(args)
    cli.main(["3000", "a"])
    assert configs == [read_config(config_path())]


def test_no_command_shows_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 2
    assert capsys.readouterr().err.startswith("Usage: wildburrow [OPTIONS] COMMAND [ARGS]...\n")


def test_login_asks_for_each_setting_in_a_terminal(typed: Typist, tmp_path: Path) -> None:
    key = tmp_path / "id_test"
    key.write_text("private")
    typed("tunnel.example.com", ENTER, ENTER, ENTER, "\b" * 4, "2200", ENTER, str(key), ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()) == ClientConfig("tunnel.example.com", 2200, identity=str(key))
    assert typed.showed(
        "? Server tunnel.example.com",
        "? Connect over ssh: your ssh binary, on port 2222",
        "? Log in with key: your SSH key",
        "? SSH port 2200",
        f"? SSH key (empty lets ssh pick) {key}",
    )


def test_login_over_websocket_with_a_token(typed: Typist) -> None:
    typed("tunnel.example.com", ENTER, DOWN, ENTER, DOWN, DOWN, ENTER, ENTER, "secret", ENTER)
    assert cli.main(["login"]) == 0
    assert typed.showed(
        "? Connect over websocket: wss:// on port 443, which gets through most proxies and firewalls",
        "? Log in with token: one made with `wildburrow token NAME` on the server",
        "? Token ******",
    )
    assert read_config(config_path()) == ClientConfig(
        "tunnel.example.com", transport="websocket", auth="token", token="secret"
    )


def test_login_starts_from_the_saved_settings(typed: Typist) -> None:
    write_config(config_path(), ClientConfig("old.example.com", 2201, transport="ssh", auth="password", user="me"))
    typed(ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()) == ClientConfig(
        "old.example.com", 2201, transport="ssh", auth="password", user="me"
    )


def test_login_offers_only_what_the_transport_can_do(typed: Typist) -> None:
    write_config(config_path(), ClientConfig("s.example.com", transport="websocket", auth="token", token="t"))
    # From websocket and token, down wraps round to ssh, where token isn't offered and key comes first.
    typed(ENTER, DOWN, ENTER, DOWN, ENTER, ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()) == ClientConfig("s.example.com", auth="password", token="t")


def test_login_answers_are_checked(typed: Typist) -> None:
    # An empty server, then a port that isn't a number, are each refused and asked again.
    typed(ENTER, "s", ENTER, ENTER, ENTER, "x", ENTER, "\b", ENTER, ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()) == ClientConfig("s")


def test_login_refuses_a_missing_key_file(typed: Typist, tmp_path: Path) -> None:
    typed("s", ENTER, ENTER, ENTER, ENTER, str(tmp_path / "missing"), ENTER, "\b" * 200, ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()) == ClientConfig("s", identity="")


def test_login_defaults_to_the_first_key_it_finds(typed: Typist, tmp_path: Path) -> None:
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text("private")
    typed("s", ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()).identity == str(tmp_path / ".ssh" / "id_ed25519")


def test_login_can_be_cancelled(typed: Typist, capsys: pytest.CaptureFixture[str]) -> None:
    typed("tunnel", CTRL_C)
    assert cli.main(["login"]) == 1
    assert capsys.readouterr().err == "aborted\n"
    assert read_config(config_path()) is None


def test_login_without_a_terminal_needs_the_server(no_terminal: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["login"]) == 2
    assert capsys.readouterr().err == "missing SERVER: pass it, or run `wildburrow login` in a terminal to be asked\n"


def test_login_options_still_need_the_server(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["login", "--ssh-port", "2200"]) == 2
    assert capsys.readouterr().err.splitlines()[-1] == "Error: Missing argument 'SERVER'."
    assert read_config(config_path()) is None


@pytest.mark.parametrize("args", [["--token", "t"], ["--reconnect"]])
def test_login_with_any_option_asks_nothing(args: list[str], typed: Typist) -> None:
    assert cli.main(["login", *args]) == 2


def test_logout_forgets_the_server(capsys: pytest.CaptureFixture[str], no_terminal: None) -> None:
    write_config(config_path(), ClientConfig("s.example.com"))
    assert cli.main(["logout"]) == 0
    assert not config_path().exists()
    assert capsys.readouterr().out == f"removed {config_path()}\n"


@pytest.mark.parametrize(("answer", "code", "kept"), [("y", 0, False), ("n", 1, True), (ENTER, 0, False)])
def test_logout_asks_first_in_a_terminal(typed: Typist, answer: str, code: int, kept: bool) -> None:
    write_config(config_path(), ClientConfig("s.example.com"))
    typed(answer)
    assert cli.main(["logout"]) == code
    assert config_path().exists() is kept
    assert typed.showed(f"? Forget s.example.com? {'No' if kept else 'Yes'}")


def test_logout_yes_skips_the_question(typed: Typist) -> None:
    write_config(config_path(), ClientConfig("s.example.com"))
    assert cli.main(["logout", "-y"]) == 0
    assert not config_path().exists()


def test_logout_without_a_login(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["logout"]) == 0
    assert capsys.readouterr().out == "not logged in\n"


HELP = Path(__file__).parent / "help"
PAGES = [
    [], ["connect"], ["login"], ["logout"], ["serve"], ["hash-password"], ["token"],
    ["service"], ["service", "install"], ["service", "edit"], ["service", "uninstall"], ["service", "status"],
]  # fmt: skip


@pytest.mark.parametrize("page", PAGES, ids=lambda page: "-".join(page) or "wildburrow")
def test_help(page: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    available = plugins.available
    monkeypatch.setattr(
        plugins, "available", lambda kind: {n: ep for n, ep in available(kind).items() if ep.dist.name == "wildburrow"}
    )
    monkeypatch.setenv("COLUMNS", "100")
    assert cli.main([*page, "--help"]) == 0
    assert capsys.readouterr().out == (HELP / f"{'-'.join(page) or 'wildburrow'}.txt").read_text()


def test_login_defaults_to_the_saved_key(typed: Typist, tmp_path: Path) -> None:
    key = tmp_path / "saved_key"
    key.write_text("private")
    write_config(config_path(), ClientConfig("s", identity=str(key)))
    typed(ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()).identity == str(key)


def test_importing_the_module_runs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "wildburrow.__main__", raising=False)
    monkeypatch.setattr(cli, "main", lambda: pytest.fail("ran"))
    import wildburrow.__main__  # noqa: F401


def test_settings_follow_the_plugins_installed_at_each_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["serve", "--help"]) == 0
    assert "--dns-cloudflare-api-token" in capsys.readouterr().out
    available = plugins.available
    monkeypatch.setattr(plugins, "available", lambda kind: {} if kind == "dns" else available(kind))
    assert cli.main(["serve", "--help"]) == 0
    assert "--dns-cloudflare-api-token" not in capsys.readouterr().out
    block_import(monkeypatch, "wildburrow.config")
    assert cli.main(["serve"]) == 2
    assert capsys.readouterr().err == server_cli.SERVER_EXTRA + "\n"


@pytest.mark.parametrize(("answer", "problem"), [("x", None), (" ", "required"), ("", "required")])
def test_required_login_answers(answer: str, problem: str | None) -> None:
    assert client_cli._required(answer) == problem


def test_key_file_login_answers(tmp_path: Path) -> None:
    (tmp_path / "key").write_text("private")
    assert client_cli._key_file("") is None
    assert client_cli._key_file(f" {tmp_path / 'key'} ") is None
    assert client_cli._key_file(str(tmp_path / "missing")) == "no such file"
    assert client_cli._key_file(str(tmp_path)) == "no such file"


def test_login_port_must_be_a_number(typed: Typist) -> None:
    typed("s", ENTER, ENTER, ENTER, "\b" * 4, "x", ENTER, "\b", "22", ENTER, ENTER)
    assert cli.main(["login"]) == 0
    assert read_config(config_path()).ssh_port == 22
    assert client_cli._port("x") == "a port number"
    assert client_cli._port("22") is None


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, EOFError])
def test_interrupting_a_prompt_aborts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], interrupt: type[BaseException]
) -> None:
    def getpass(prompt: str) -> str:
        raise interrupt

    monkeypatch.setattr(server_cli.getpass, "getpass", getpass)
    assert cli.main(["hash-password"]) == 1
    assert capsys.readouterr().err == "aborted\n"
