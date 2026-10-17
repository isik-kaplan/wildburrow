import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from wildburrow import envfile, service
from wildburrow.service import Account, Config, ServiceError
from wildburrow.service.launchd import Launchd
from wildburrow.service.systemd import Systemd

ME = Account("me", os.geteuid(), os.getegid())
OTHER = Account("other", ME.uid + 1, ME.gid + 1)


class Commands:
    """Stands in for the service manager commands: records each, and answers from `replies`."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.replies: dict[str, tuple[int, str, str]] = {}

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs == {"capture_output": True, "text": True, "check": False}
        self.calls.append(list(command))
        code, out, err = self.replies.get(" ".join(command), (0, "", ""))
        return subprocess.CompletedProcess(command, code, out, err)


@pytest.fixture
def commands(monkeypatch: pytest.MonkeyPatch) -> Commands:
    fake = Commands()
    monkeypatch.setattr(service.subprocess, "run", fake)
    return fake


def test_checked_names_the_failing_command(commands: Commands) -> None:
    commands.replies["systemctl start x"] = (1, "", "  Unit x not found.\n")
    commands.replies["launchctl print y"] = (2, "printed instead\n", "")
    with pytest.raises(ServiceError, match=r"^`systemctl start x` failed: Unit x not found\.$"):
        service.checked("systemctl", "start", "x")
    with pytest.raises(ServiceError, match=r"^`launchctl print y` failed: printed instead$"):
        service.checked("launchctl", "print", "y")
    commands.replies["true"] = (0, "out", "")
    assert service.checked("true") == "out"


def test_run_really_runs() -> None:
    result = service.run(sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)")
    assert (result.returncode, result.stdout, result.stderr) == (3, "out\n", "err\n")


def test_the_service_runs_this_install() -> None:
    assert service.command() == [sys.executable, "-m", "wildburrow", "serve"]


@pytest.fixture
def homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(service, "HOMES", (tmp_path / "home",))
    return tmp_path / "home"


def test_an_install_outside_any_home_runs_as_a_throwaway_user(homes: Path, tmp_path: Path) -> None:
    (tmp_path / "opt").mkdir()
    assert service.install_account((str(tmp_path / "opt"), str(tmp_path / "opt"))) == Account(None)


@pytest.mark.parametrize("which", [0, 1])
def test_an_install_in_a_home_runs_as_its_owner(homes: Path, tmp_path: Path, which: int) -> None:
    (homes / "me" / "venv").mkdir(parents=True)
    (tmp_path / "opt").mkdir()
    prefixes = [str(tmp_path / "opt"), str(tmp_path / "opt")]
    prefixes[which] = str(homes / "me" / "venv")
    owner = service.pwd.getpwuid(os.geteuid())
    assert service.install_account((prefixes[0], prefixes[1])) == Account(owner.pw_name, owner.pw_uid, owner.pw_gid)


def test_a_link_into_a_home_counts_as_in_it(homes: Path, tmp_path: Path) -> None:
    (homes / "me").mkdir(parents=True)
    (tmp_path / "link").symlink_to(homes / "me")
    assert service.install_account((str(tmp_path / "link"), str(tmp_path / "link"))).name is not None


def test_the_default_homes_are_the_usual_ones() -> None:
    assert (Path("/home"), Path("/root"), Path("/Users")) == service.HOMES


@pytest.mark.parametrize(
    ("platform", "systemd", "kind"), [("darwin", False, Launchd), ("linux", True, Systemd), ("linux2", True, Systemd)]
)
def test_the_manager_follows_the_platform(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, platform: str, systemd: bool, kind: type
) -> None:
    monkeypatch.setattr(service.sys, "platform", platform)
    if systemd:
        (tmp_path / "run/systemd/system").mkdir(parents=True)
    manager = service.manager(tmp_path)
    assert isinstance(manager, kind)
    assert manager.root == tmp_path


@pytest.mark.parametrize(("platform", "systemd"), [("linux", False), ("freebsd14", True), ("win32", True)])
def test_other_systems_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, platform: str, systemd: bool
) -> None:
    monkeypatch.setattr(service.sys, "platform", platform)
    if systemd:
        (tmp_path / "run/systemd/system").mkdir(parents=True)
    with pytest.raises(ServiceError) as error:
        service.manager(tmp_path)
    assert str(error.value) == "services need systemd (Linux) or launchd (macOS); run `wildburrow serve` some other way"


def test_the_manager_defaults_to_this_system(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.sys, "platform", "darwin")
    assert service.manager().root == Path("/")


@pytest.fixture(params=[Systemd, Launchd], ids=["systemd", "launchd"])
def manager(request: pytest.FixtureRequest, tmp_path: Path, commands: Commands) -> service.Manager:
    return request.param(tmp_path)


def test_config_keeps_multi_line_values_in_files_of_their_own(manager: service.Manager, tmp_path: Path) -> None:
    config = Config(manager)
    settings = {"WILDBURROW_DOMAIN": "t.example.com", "WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS": "key one\nkey two"}
    config.save(settings, ME)
    keys = tmp_path / "etc/wildburrow/auth_key_authorized_keys"
    assert envfile.read(tmp_path / "etc/wildburrow/env") == {
        "WILDBURROW_DOMAIN": "t.example.com",
        "WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS_FILE": str(keys),
    }
    assert keys.read_text() == "key one\nkey two\n"
    assert stat.S_IMODE((tmp_path / "etc/wildburrow/env").stat().st_mode) == 0o600
    assert stat.S_IMODE(keys.stat().st_mode) == 0o644
    assert stat.S_IMODE((tmp_path / "etc/wildburrow").stat().st_mode) == 0o755
    assert config.load() == settings


def test_config_load_leaves_outside_files_alone(manager: service.Manager, tmp_path: Path) -> None:
    config = Config(manager)
    config.dir.mkdir(parents=True)
    envfile.write(config.env, {"WILDBURROW_DOMAIN_FILE": "/run/secrets/domain"}, 0o600)
    assert config.load() == {"WILDBURROW_DOMAIN_FILE": "/run/secrets/domain"}


def test_config_save_drops_files_it_no_longer_needs(manager: service.Manager, tmp_path: Path) -> None:
    config = Config(manager)
    config.save({"WILDBURROW_AUTH_TOKEN_HASHES": "a:1\nb:2"}, ME)
    config.save({"WILDBURROW_DOMAIN": "x.example.com"}, ME)
    assert sorted(path.name for path in config.dir.iterdir()) == ["env"]


def test_config_remove(manager: service.Manager) -> None:
    config = Config(manager)
    config.remove()
    config.save({"WILDBURROW_AUTH_TOKEN_HASHES": "a:1\nb:2"}, ME)
    config.remove()
    assert not config.dir.exists()


@pytest.fixture
def chowns(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int, int]]:
    calls: list[tuple[str, int, int]] = []
    monkeypatch.setattr(service.os, "chown", lambda path, uid, gid: calls.append((Path(path).name, uid, gid)))
    return calls


@pytest.mark.parametrize(
    ("account", "owned"),
    [
        (Account(None), False),
        (ME, False),
        (Account("other", ME.uid, ME.gid + 1), True),
        (Account("other", ME.uid + 1, ME.gid), True),
    ],
)
def test_own_changes_only_what_another_account_needs(
    tmp_path: Path, chowns: list[tuple[str, int, int]], account: Account, owned: bool
) -> None:
    service.own(tmp_path, account)
    assert chowns == ([(tmp_path.name, account.uid, account.gid)] if owned else [])


def test_launchd_hands_the_settings_to_the_account(tmp_path: Path, commands: Commands, chowns: list) -> None:
    Config(Launchd(tmp_path)).save({"WILDBURROW_AUTH_TOKEN_HASHES": "a:1\nb:2"}, OTHER)
    assert sorted(chowns) == [("auth_token_hashes", OTHER.uid, OTHER.gid), ("env", OTHER.uid, OTHER.gid)]


def test_systemd_keeps_the_settings_for_root(tmp_path: Path, commands: Commands, chowns: list) -> None:
    Config(Systemd(tmp_path)).save({"WILDBURROW_AUTH_TOKEN_HASHES": "a:1\nb:2"}, OTHER)
    assert chowns == []


UNIT = """[Unit]
Description=wildburrow tunnel server
Wants=network-online.target
After=network-online.target

[Service]
ExecStart={command}
EnvironmentFile=/etc/wildburrow/env
Environment=WILDBURROW_DATA_DIR=%S/wildburrow
{user}
StateDirectory=wildburrow
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome={home}
PrivateTmp=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


@pytest.mark.parametrize(
    ("account", "user", "home"), [(Account(None), "DynamicUser=yes", "yes"), (ME, "User=me", "read-only")]
)
def test_systemd_install(
    tmp_path: Path, commands: Commands, monkeypatch: pytest.MonkeyPatch, account: Account, user: str, home: str
) -> None:
    monkeypatch.setattr(service.sys, "executable", '/opt/my "py"\\bin/python')
    manager = Systemd(tmp_path)
    assert not manager.installed()
    manager.install(account)
    assert manager.installed()
    command = '"/opt/my \\"py\\"\\\\bin/python" "-m" "wildburrow" "serve"'
    assert (tmp_path / "etc/systemd/system/wildburrow.service").read_text() == UNIT.format(
        command=command, user=user, home=home
    )
    assert stat.S_IMODE((tmp_path / "etc/systemd/system/wildburrow.service").stat().st_mode) == 0o644
    assert commands.calls == [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "wildburrow"]]


def test_systemd_install_reports_a_failed_start(tmp_path: Path, commands: Commands) -> None:
    commands.replies["systemctl enable --now wildburrow"] = (1, "", "Job failed.")
    with pytest.raises(ServiceError, match=r"^`systemctl enable --now wildburrow` failed: Job failed\.$"):
        Systemd(tmp_path).install(Account(None))


def test_systemd_uninstall_tolerates_a_stopped_service(tmp_path: Path, commands: Commands) -> None:
    manager = Systemd(tmp_path)
    manager.install(Account(None))
    commands.calls.clear()
    commands.replies["systemctl disable --now wildburrow"] = (1, "", "not loaded")
    manager.uninstall()
    manager.uninstall()
    assert not manager.installed()
    assert commands.calls == [["systemctl", "disable", "--now", "wildburrow"], ["systemctl", "daemon-reload"]] * 2


def test_systemd_restart_status_and_logs(tmp_path: Path, commands: Commands) -> None:
    manager = Systemd(tmp_path)
    manager.restart()
    commands.replies["systemctl is-active wildburrow"] = (3, "inactive\n", "")
    assert manager.status() == "inactive"
    commands.replies["systemctl is-active wildburrow"] = (4, "", "")
    assert manager.status() == "unknown"
    assert manager.logs() == "journalctl -u wildburrow -f"
    assert manager.kind == "systemd"
    assert manager.data_dirs() == [tmp_path / "var/lib/wildburrow", tmp_path / "var/lib/private/wildburrow"]
    assert manager.file_owner(ME) == Account(None)
    assert commands.calls[0] == ["systemctl", "restart", "wildburrow"]
    commands.replies["systemctl restart wildburrow"] = (1, "", "failed")
    with pytest.raises(ServiceError):
        manager.restart()


@pytest.mark.parametrize(("account", "user"), [(Account(None), None), (ME, "me")])
def test_launchd_install(
    tmp_path: Path, commands: Commands, monkeypatch: pytest.MonkeyPatch, account: Account, user: str | None
) -> None:
    monkeypatch.setattr(service.sys, "executable", "/opt/py")
    manager = Launchd(tmp_path)
    assert not manager.installed()
    manager.install(account)
    assert manager.installed()
    plist_path = tmp_path / "Library/LaunchDaemons/wildburrow.plist"
    expected = {
        "Label": "wildburrow",
        "ProgramArguments": ["/opt/py", "-m", "wildburrow", "serve", "--env-file", "/etc/wildburrow/env"],
        "EnvironmentVariables": {"WILDBURROW_DATA_DIR": "/Library/Application Support/wildburrow"},
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": "/Library/Logs/wildburrow.log",
        "StandardErrorPath": "/Library/Logs/wildburrow.log",
    } | ({"UserName": user} if user else {})
    assert plistlib.loads(plist_path.read_bytes()) == expected
    assert stat.S_IMODE(plist_path.stat().st_mode) == 0o644
    assert stat.S_IMODE((tmp_path / "Library/Application Support/wildburrow").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "Library/Logs/wildburrow.log").stat().st_mode) == 0o640
    assert commands.calls == [["launchctl", "bootstrap", "system", str(plist_path)]]


def test_launchd_install_hands_its_files_to_the_account(tmp_path: Path, commands: Commands, chowns: list) -> None:
    Launchd(tmp_path).install(OTHER)
    assert chowns == [("wildburrow", OTHER.uid, OTHER.gid), ("wildburrow.log", OTHER.uid, OTHER.gid)]


def test_launchd_uninstall(tmp_path: Path, commands: Commands) -> None:
    manager = Launchd(tmp_path)
    manager.install(Account(None))
    commands.calls.clear()
    commands.replies["launchctl bootout system/wildburrow"] = (3, "", "No such process")
    manager.uninstall()
    manager.uninstall()
    assert not manager.installed()
    assert not (tmp_path / "Library/Logs/wildburrow.log").exists()
    assert (tmp_path / "Library/Application Support/wildburrow").exists()
    assert commands.calls == [["launchctl", "bootout", "system/wildburrow"]] * 2


PRINTED = """system/wildburrow = {
\tactive count = 1
\tpath = /Library/LaunchDaemons/wildburrow.plist
\tstate = running
\tprogram = /opt/py
}
"""


@pytest.mark.parametrize(
    ("reply", "status"),
    [
        ((0, PRINTED, ""), "running"),
        ((0, PRINTED.replace("running", "not running"), ""), "not running"),
        ((113, "", "Could not find service"), "not loaded"),
    ],
)
def test_launchd_status(tmp_path: Path, commands: Commands, reply: tuple[int, str, str], status: str) -> None:
    commands.replies["launchctl print system/wildburrow"] = reply
    assert Launchd(tmp_path).status() == status


def test_launchd_status_splits_at_the_first_equals(tmp_path: Path, commands: Commands) -> None:
    commands.replies["launchctl print system/wildburrow"] = (0, "\tstate = odd = value\n", "")
    assert Launchd(tmp_path).status() == "odd = value"


def test_launchd_reinstalls_over_what_it_left(tmp_path: Path, commands: Commands) -> None:
    manager = Launchd(tmp_path)
    manager.install(Account(None))
    manager.uninstall()
    manager.install(Account(None))
    assert manager.installed()


def test_config_directory_is_readable_whatever_the_umask(manager: service.Manager) -> None:
    old = os.umask(0)
    try:
        Config(manager).save({"WILDBURROW_DOMAIN": "x.example.com"}, ME)
    finally:
        os.umask(old)
    assert stat.S_IMODE(Config(manager).dir.stat().st_mode) == 0o755


def test_the_owner_is_the_installs_own(homes: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (homes / "me" / "venv").mkdir(parents=True)
    (tmp_path / "base").mkdir()
    owners = {str(homes / "me" / "venv"): ME.uid, str(tmp_path / "base"): ME.uid + 1}
    real_stat = Path.stat
    monkeypatch.setattr(
        Path,
        "stat",
        lambda self, **kw: SimpleNamespace(st_uid=owners[str(self)]) if str(self) in owners else real_stat(self, **kw),
    )
    monkeypatch.setattr(
        service.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name=f"user{uid}", pw_uid=uid, pw_gid=7)
    )
    assert service.install_account((str(homes / "me" / "venv"), str(tmp_path / "base"))) == Account(
        f"user{ME.uid}", ME.uid, 7
    )


def test_launchd_status_needs_a_state(tmp_path: Path, commands: Commands) -> None:
    commands.replies["launchctl print system/wildburrow"] = (0, "system/wildburrow = {\n\tstated = x\n}\n", "")
    with pytest.raises(ServiceError, match=r"^`launchctl print system/wildburrow` shows no state$"):
        Launchd(tmp_path).status()


def test_launchd_restart_and_logs(tmp_path: Path, commands: Commands) -> None:
    manager = Launchd(tmp_path)
    manager.restart()
    assert commands.calls == [["launchctl", "kickstart", "-k", "system/wildburrow"]]
    assert manager.logs() == "tail -f '/Library/Logs/wildburrow.log'"
    assert manager.kind == "launchd"
    assert manager.data_dirs() == [tmp_path / "Library/Application Support/wildburrow"]
    assert manager.file_owner(ME) == ME


def test_paths_seen_by_the_running_system() -> None:
    assert Path("/etc/wildburrow/env") == service.ENV_PATH
