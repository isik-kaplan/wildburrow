import dataclasses
import os
from pathlib import Path

import asyncssh
import pytest
from argon2 import PasswordHasher

from tests.unit.conftest import DOWN, ENTER, Typist
from tests.unit.test_service import Commands
from wildburrow import cli, envfile, plugins, service
from wildburrow.cli import service as service_cli
from wildburrow.config import SECRET
from wildburrow.service import Account, Config
from wildburrow.service.launchd import Launchd
from wildburrow.service.systemd import Systemd

P = "WILDBURROW_"
KEYS = f"{P}AUTH_KEY_AUTHORIZED_KEYS"
DOMAIN = "tunnel.example.com"


def public_key(comment: str) -> str:
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    return key.export_public_key().decode().strip()


LAPTOP, PHONE = public_key("laptop"), public_key("phone")
HASH = PasswordHasher().hash("secret")


@pytest.fixture(autouse=True)
def builtin_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    available = plugins.available
    monkeypatch.setattr(
        plugins, "available", lambda kind: {n: ep for n, ep in available(kind).items() if ep.dist.name == "wildburrow"}
    )


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(f"# mine\n{LAPTOP}\n")
    monkeypatch.setattr(service_cli, "_home", lambda: home)
    return home


@pytest.fixture
def commands(monkeypatch: pytest.MonkeyPatch) -> Commands:
    fake = Commands()
    fake.replies["systemctl is-active wildburrow"] = (0, "active\n", "")
    monkeypatch.setattr(service.subprocess, "run", fake)
    return fake


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, commands: Commands, home: Path) -> Path:
    root = tmp_path / "root"
    monkeypatch.setattr(service_cli, "find_manager", lambda: Systemd(root))
    monkeypatch.setattr(service_cli, "install_account", lambda: Account(None))
    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 0)
    return root


def settings(root: Path) -> dict[str, str]:
    return Config(Systemd(root)).load()


def installed(root: Path) -> bool:
    return (root / "etc/systemd/system/wildburrow.service").exists()


REPORT = """wildburrow is active as a systemd service
  settings: /etc/wildburrow/env (change them with `wildburrow service edit`)
  logs: journalctl -u wildburrow -f
"""


def test_install_from_options(root: Path, commands: Commands, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        cli.main(["service", "install", f"--domain={DOMAIN}", "--http-port", "8080", "--no-http-proxy-protocol"]) == 0
    )
    assert settings(root) == {
        f"{P}DOMAIN": DOMAIN,
        f"{P}HTTP_PORT": "8080",
        f"{P}HTTP_PROXY_PROTOCOL": "off",
        KEYS: f"# mine\n{LAPTOP}",
    }
    assert installed(root)
    assert commands.calls == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "wildburrow"],
        ["systemctl", "is-active", "wildburrow"],
    ]
    assert capsys.readouterr().out == REPORT


def test_install_reads_option_files_into_its_own_copy(root: Path, tmp_path: Path) -> None:
    keys = tmp_path / "keys"
    keys.write_text(f"{LAPTOP}\n{PHONE}\n")
    domain = tmp_path / "domain"
    domain.write_text(DOMAIN + "\n")
    assert (
        cli.main(["service", "install", "--domain-file", str(domain), "--auth-key-authorized-keys-file", str(keys)])
        == 0
    )
    copy = root / "etc/wildburrow/auth_key_authorized_keys"
    assert envfile.read(root / "etc/wildburrow/env") == {f"{P}DOMAIN": DOMAIN, f"{KEYS}_FILE": str(copy)}
    assert copy.read_text() == f"{LAPTOP}\n{PHONE}\n"


def test_install_reports_an_unreadable_option_file(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing"
    assert cli.main(["service", "install", f"--domain={DOMAIN}", "--auth-key-authorized-keys-file", str(missing)]) == 2
    assert capsys.readouterr().err == f"{KEYS}_FILE: [Errno 2] No such file or directory: '{missing}'\n"
    assert not installed(root)


def test_install_without_keys_of_its_own(root: Path, home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (home / ".ssh" / "authorized_keys").unlink()
    assert cli.main(["service", "install", f"--domain={DOMAIN}"]) == 2
    assert capsys.readouterr().err == (
        f"no keys to let in: {home / '.ssh/authorized_keys'} doesn't exist; pass --auth-key-authorized-keys-file\n"
    )
    assert (
        cli.main(
            ["service", "install", f"--domain={DOMAIN}", "--auth", "token", "--auth-token-hashes", "a:" + "0" * 64]
        )
        == 0
    )
    assert KEYS not in settings(root)


@pytest.mark.parametrize("keys", ["", "# only a comment\n"])
def test_install_refuses_keys_that_hold_none(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], keys: str
) -> None:
    (tmp_path / "keys").write_text(keys)
    assert (
        cli.main(["service", "install", f"--domain={DOMAIN}", f"--auth-key-authorized-keys-file={tmp_path / 'keys'}"])
        == 2
    )
    assert capsys.readouterr().err == "no keys to let in: the authorized keys given hold none\n"
    assert not installed(root)


def test_install_checks_the_settings_like_serve(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["service", "install", "--domain=bad_domain"]) == 2
    assert capsys.readouterr().err == f"configuration error: {P}DOMAIN: 'bad_domain' is not a valid domain\n"
    assert not installed(root)
    assert not (root / "etc/wildburrow").exists()


def test_install_closes_the_dns_plugin_it_checked(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[bool] = []

    async def aclose(self: object) -> None:
        closed.append(True)

    monkeypatch.setattr("wildburrow.dns.cloudflare.CloudflareDNS.aclose", aclose)
    assert (
        cli.main(["service", "install", f"--domain={DOMAIN}", "--dns=cloudflare", "--dns-cloudflare-api-token=cf"]) == 0
    )
    assert closed == [True]


def test_install_has_no_data_dir_option(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["service", "install", f"--domain={DOMAIN}", "--data-dir", "/srv"]) == 2
    assert "No such option '--data-dir'" in capsys.readouterr().err


def test_install_refuses_to_replace_an_install(
    root: Path, commands: Commands, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["service", "install", f"--domain={DOMAIN}"]) == 0
    capsys.readouterr()
    assert cli.main(["service", "install", "--domain=other.example.com"]) == 1
    assert capsys.readouterr().err == "already installed: change it with `wildburrow service edit`, or pass --force\n"
    commands.calls.clear()
    assert cli.main(["service", "install", "--domain=other.example.com", "--force"]) == 0
    assert settings(root)[f"{P}DOMAIN"] == "other.example.com"
    assert commands.calls[:2] == [["systemctl", "disable", "--now", "wildburrow"], ["systemctl", "daemon-reload"]]


def test_install_without_settings_or_a_terminal(
    root: Path, no_terminal: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["service", "install"]) == 2
    assert capsys.readouterr().err == (
        "no settings given: pass them as options, or run `wildburrow service install` in a terminal\n"
    )
    assert cli.main(["service", "install", "--force"]) == 2


def test_install_asks_in_a_terminal(root: Path, typed: Typist, home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    typed("Tunnel.Example.COM", ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["service", "install"]) == 0
    assert settings(root) == {
        f"{P}DOMAIN": DOMAIN,
        f"{P}TRANSPORTS": "ssh",
        KEYS: f"# mine\n{LAPTOP}",
    }
    summary = f"  domain: {DOMAIN}\n  transports: ssh\n  auth_key_authorized_keys: (1 keys)\n"
    assert capsys.readouterr().out == "Keys allowed to open tunnels:\n" + summary + REPORT
    assert typed.showed(
        "? Domain the tunnels live under Tunnel.Example.COM",
        "? Certificates none: plain HTTP on port 80",
        "? Transports ssh: clients connect on port 2222",
        f"? An authorized_keys file to copy them from {home / '.ssh/authorized_keys'}",
        "? Save these and start the server? Yes",
    )


def test_install_asks_for_https_and_its_secret(
    root: Path, typed: Typist, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    typed(DOMAIN, ENTER, DOWN, ENTER, "cf-token", ENTER, "me@example.com", ENTER, DOWN, ENTER, ENTER, "y")
    assert cli.main(["service", "install"]) == 0
    assert settings(root) == {
        f"{P}DOMAIN": DOMAIN,
        f"{P}DNS": "cloudflare",
        f"{P}DNS_CLOUDFLARE_API_TOKEN": "cf-token",
        f"{P}ACME_EMAIL": "me@example.com",
        f"{P}TRANSPORTS": "ssh,websocket",
        KEYS: f"# mine\n{LAPTOP}",
    }
    out = capsys.readouterr().out
    assert "  dns_cloudflare_api_token: (hidden)\n" in out
    assert "cf-token" not in out
    assert typed.showed(
        f"? Domain the tunnels live under {DOMAIN}",
        "? Certificates cloudflare: HTTPS, proving the domain through cloudflare",
        "? cloudflare api token ********",
        "? E-mail for the certificate authority (optional) me@example.com",
        "? Transports ssh, and websocket on port 443 for clients behind proxies or firewalls",
        f"? An authorized_keys file to copy them from {home / '.ssh/authorized_keys'}",
        "? Save these and start the server? Yes",
    )


def test_install_answers_are_checked(root: Path, typed: Typist, home: Path, tmp_path: Path) -> None:
    (tmp_path / "empty").write_text("# nothing\n")
    keys, missing, empty = str(home / ".ssh/authorized_keys"), str(tmp_path / "missing"), str(tmp_path / "empty")
    typed(
        *("nodots", ENTER, "\b" * 6, "bad_label.com", ENTER, "\b" * 13, DOMAIN, ENTER),
        *(DOWN, ENTER, ENTER, "cf", ENTER, ENTER, ENTER),
        *("\b" * len(keys), missing, ENTER, "\b" * len(missing)),
        *(empty, ENTER, "\b" * len(empty), keys, ENTER, ENTER),
    )
    assert cli.main(["service", "install"]) == 0
    assert settings(root)[f"{P}DOMAIN"] == DOMAIN
    assert settings(root)[f"{P}DNS_CLOUDFLARE_API_TOKEN"] == "cf"
    assert f"{P}ACME_EMAIL" not in settings(root)


def test_install_can_be_declined(root: Path, typed: Typist, capsys: pytest.CaptureFixture[str]) -> None:
    typed(DOMAIN, ENTER, ENTER, ENTER, ENTER, "n")
    assert cli.main(["service", "install"]) == 1
    assert capsys.readouterr().err == "aborted\n"
    assert not installed(root)


def install(root: Path, *options: str) -> None:
    assert cli.main(["service", "install", f"--domain={DOMAIN}", *options]) == 0


def test_edit_changes_only_the_options_given(root: Path, commands: Commands) -> None:
    install(root, "--http-port", "8080", "--ssh-port", "2200")
    commands.calls.clear()
    assert cli.main(["service", "edit", "--http-port", "9090"]) == 0
    assert settings(root) == {
        f"{P}DOMAIN": DOMAIN,
        f"{P}HTTP_PORT": "9090",
        f"{P}SSH_PORT": "2200",
        KEYS: f"# mine\n{LAPTOP}",
    }
    assert commands.calls[0] == ["systemctl", "restart", "wildburrow"]


def test_edit_asks_with_the_current_answers(root: Path, typed: Typist) -> None:
    install(root, "--dns=cloudflare", "--dns-cloudflare-api-token=old", "--acme-email=a@example.com")
    before = settings(root)
    typed(ENTER, ENTER, ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["service", "edit"]) == 0
    assert settings(root) == before | {f"{P}TRANSPORTS": "ssh"}
    assert typed.showed(
        f"? Domain the tunnels live under {DOMAIN}",
        "? Certificates cloudflare: HTTPS, proving the domain through cloudflare",
        "? cloudflare api token (empty keeps the current one)",
        "? E-mail for the certificate authority (optional) a@example.com",
        "? Transports ssh: clients connect on port 2222",
        "? Keep the 1 keys allowed to open tunnels? Yes",
        "? Save these and start the server? Yes",
    )


def test_edit_can_drop_https_and_replace_the_keys(root: Path, typed: Typist, tmp_path: Path, home: Path) -> None:
    install(
        root, "--dns=cloudflare", "--dns-cloudflare-api-token=old", "--acme-email=a@example.com", "--dns-manage-records"
    )
    (tmp_path / "new").write_text(f"{LAPTOP}\n{PHONE}\n")
    keys = str(home / ".ssh/authorized_keys")
    typed(ENTER, DOWN, ENTER, ENTER, "n", "\b" * len(keys), str(tmp_path / "new"), ENTER, ENTER)
    assert cli.main(["service", "edit"]) == 0
    assert settings(root) == {
        f"{P}DOMAIN": DOMAIN,
        f"{P}DNS_MANAGE_RECORDS": "on",
        f"{P}TRANSPORTS": "ssh",
        KEYS: f"{LAPTOP}\n{PHONE}",
    }
    assert typed.showed("? Keep the 1 keys allowed to open tunnels? No")


def test_edit_asks_for_keys_whenever_key_auth_is_on(root: Path, typed: Typist) -> None:
    install(root, "--auth=key,token", "--auth-token-hashes=" + "a:" + "0" * 64)
    typed(ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["service", "edit"]) == 0
    assert typed.showed("? Keep the 1 keys allowed to open tunnels? Yes")


def test_install_lets_in_the_invokers_keys_alongside_other_methods(root: Path) -> None:
    install(root, "--auth=password,key", "--auth-password-hash=" + HASH)
    assert settings(root)[KEYS] == f"# mine\n{LAPTOP}"


def test_edit_keeps_an_unusual_transport_on_offer(root: Path, typed: Typist) -> None:
    install(root, "--transports=websocket")
    typed(ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["service", "edit"]) == 0
    assert settings(root)[f"{P}TRANSPORTS"] == "websocket"


def test_edit_asks_no_keys_without_key_auth(root: Path, typed: Typist) -> None:
    install(root, "--auth=token", "--auth-token-hashes=" + "a:" + "0" * 64)
    typed(ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["service", "edit"]) == 0
    assert KEYS not in settings(root)


def test_edit_needs_an_install(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["service", "edit", "--http-port", "1"]) == 1
    assert capsys.readouterr().err == "not installed: run `wildburrow service install`\n"


def test_edit_without_changes_or_a_terminal(root: Path, no_terminal: None, capsys: pytest.CaptureFixture[str]) -> None:
    install(root)
    capsys.readouterr()
    assert cli.main(["service", "edit"]) == 2
    assert (
        capsys.readouterr().err
        == "no settings given: pass them as options, or run `wildburrow service edit` in a terminal\n"
    )


def test_uninstall_with_yes(root: Path, commands: Commands, capsys: pytest.CaptureFixture[str]) -> None:
    install(root)
    data = root / "var/lib/private/wildburrow"
    data.mkdir(parents=True)
    capsys.readouterr()
    assert cli.main(["service", "uninstall", "--yes"]) == 0
    assert not installed(root)
    assert not (root / "etc/wildburrow").exists()
    assert data.exists()
    assert capsys.readouterr().out == "removed the wildburrow service\n"
    install(root)
    capsys.readouterr()
    assert cli.main(["service", "uninstall", "-y", "--purge"]) == 0
    assert not data.exists()
    assert capsys.readouterr().out == "removed the wildburrow service and its data\n"


@pytest.mark.parametrize(
    ("keys", "code", "removed", "purged"),
    [
        ("n", 1, False, False),
        (ENTER, 1, False, False),
        ("yn", 0, True, False),
        ("yy", 0, True, True),
        ("y" + ENTER, 0, True, False),
    ],
)
def test_uninstall_asks_first(root: Path, typed: Typist, keys: str, code: int, removed: bool, purged: bool) -> None:
    install(root)
    data = root / "var/lib/wildburrow"
    data.mkdir(parents=True)
    typed(keys)
    assert cli.main(["service", "uninstall"]) == code
    assert installed(root) is not removed
    assert data.exists() is not purged
    question = "? Stop and remove the wildburrow service?"
    if removed:
        purge = "? Also delete its certificates, ACME account and SSH host key?"
        assert typed.showed(f"{question} Yes", f"{purge} {'Yes' if purged else 'No'}")
    else:
        assert typed.showed(f"{question} No")


def test_uninstall_purge_skips_that_question(root: Path, typed: Typist) -> None:
    install(root)
    (root / "var/lib/wildburrow").mkdir(parents=True)
    typed("y")
    assert cli.main(["service", "uninstall", "--purge"]) == 0
    assert not (root / "var/lib/wildburrow").exists()


def test_uninstall_without_a_terminal_needs_yes(
    root: Path, no_terminal: None, capsys: pytest.CaptureFixture[str]
) -> None:
    install(root)
    capsys.readouterr()
    assert cli.main(["service", "uninstall"]) == 2
    assert capsys.readouterr().err == "pass --yes to uninstall without being asked\n"
    assert installed(root)


def test_uninstall_when_not_installed(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["service", "uninstall", "--yes"]) == 0
    assert capsys.readouterr().out == "not installed\n"


def test_status(root: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    assert cli.main(["service", "status"]) == 1
    assert capsys.readouterr().out == "not installed\n"
    install(root)
    capsys.readouterr()
    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 1000)
    assert cli.main(["service", "status"]) == 0
    assert capsys.readouterr().out == REPORT


def test_status_on_launchd(
    tmp_path: Path, commands: Commands, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manager = Launchd(tmp_path)
    manager.plist.parent.mkdir(parents=True)
    manager.plist.write_text("")
    commands.replies["launchctl print system/wildburrow"] = (0, "\tstate = running\n", "")
    monkeypatch.setattr(service_cli, "find_manager", lambda: manager)
    assert cli.main(["service", "status"]) == 0
    assert capsys.readouterr().out == (
        "wildburrow is running as a launchd service\n"
        "  settings: /etc/wildburrow/env (change them with `wildburrow service edit`)\n"
        "  logs: tail -f '/Library/Logs/wildburrow.log'\n"
    )


@pytest.mark.parametrize("args", [["install", f"--domain={DOMAIN}"], ["edit"], ["uninstall"]])
def test_changes_go_through_sudo(
    root: Path, monkeypatch: pytest.MonkeyPatch, args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    execs: list[tuple[str, list[str]]] = []

    class Replaced(Exception):
        pass

    def execvp(file: str, argv: list[str]) -> None:
        execs.append((file, argv))
        raise Replaced

    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(service_cli.shutil, "which", lambda name: "/usr/bin/sudo" if name == "sudo" else None)
    monkeypatch.setattr(service_cli.os, "execvp", execvp)
    monkeypatch.setattr(service_cli.sys, "argv", ["wildburrow", "service", *args])
    with pytest.raises(Replaced):
        cli.main(["service", *args])
    assert execs == [("sudo", ["sudo", service_cli.sys.executable, "-m", "wildburrow", "service", *args])]
    assert capsys.readouterr().err == "this needs root; asking sudo\n"
    assert not installed(root)


def test_changes_without_sudo(root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(service_cli.shutil, "which", lambda name: None)
    assert cli.main(["service", "uninstall", "--yes"]) == 1
    assert capsys.readouterr().err == "this needs root\n"


def test_unsupported_systems(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(service.sys, "platform", "freebsd14")
    assert cli.main(["service", "status"]) == 1
    assert capsys.readouterr().err == (
        "services need systemd (Linux) or launchd (macOS); run `wildburrow serve` some other way\n"
    )


def test_the_home_is_the_invoking_users(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Entry:
        pw_dir = str(tmp_path / "them")

    monkeypatch.setattr(service_cli.pwd, "getpwnam", lambda name: Entry if name == "them" else None)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "me")
    monkeypatch.setenv("SUDO_USER", "them")
    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 0)
    assert service_cli._home() == tmp_path / "them"
    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 1000)
    assert service_cli._home() == tmp_path / "me"
    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "")
    assert service_cli._home() == tmp_path / "me"
    monkeypatch.delenv("SUDO_USER")
    assert service_cli._home() == tmp_path / "me"


def test_the_service_runs_as_the_install_account(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_cli, "install_account", lambda: Account("me", os.geteuid(), os.getegid()))
    install(root)
    assert "User=me\n" in (root / "etc/systemd/system/wildburrow.service").read_text()


@dataclasses.dataclass(frozen=True, kw_only=True)
class ZoneSettings:
    zone: str
    ttl: int = 60
    api_key: str = dataclasses.field(metadata={SECRET: True})


class ZoneDNS:
    Settings = ZoneSettings

    def __init__(self, settings: ZoneSettings) -> None:
        self.settings = settings

    async def aclose(self) -> None:
        pass


class EntryPoint:
    name = "zone"
    dist = type("Dist", (), {"name": "wildburrow"})

    def load(self) -> type:
        return ZoneDNS


def test_install_asks_for_what_a_dns_plugin_requires(
    root: Path, typed: Typist, monkeypatch: pytest.MonkeyPatch
) -> None:
    available = plugins.available
    monkeypatch.setattr(
        plugins, "available", lambda kind: available(kind) | ({"zone": EntryPoint()} if kind == "dns" else {})
    )
    typed(DOMAIN, ENTER, DOWN, DOWN, ENTER, ENTER, "example.net", ENTER, "k3y", ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["service", "install"]) == 0
    assert settings(root) == {
        f"{P}DOMAIN": DOMAIN,
        f"{P}DNS": "zone",
        f"{P}DNS_ZONE_ZONE": "example.net",
        f"{P}DNS_ZONE_API_KEY": "k3y",
        f"{P}TRANSPORTS": "ssh",
        KEYS: f"# mine\n{LAPTOP}",
    }
    assert typed.showed(
        "? Certificates zone: HTTPS, proving the domain through zone",
        "? zone zone example.net",
        "? zone api key ***",
    )
    typed(ENTER, ENTER, ENTER, ENTER, ENTER, ENTER, ENTER, ENTER)
    assert cli.main(["service", "edit"]) == 0
    assert settings(root)[f"{P}DNS_ZONE_ZONE"] == "example.net"
    assert settings(root)[f"{P}DNS_ZONE_API_KEY"] == "k3y"


@pytest.mark.parametrize(
    ("answer", "problem"),
    [
        ("example.com", None),
        (" Tunnel.Example.COM ", None),
        ("localhost", "not a domain name"),
        ("a_b.com", "not a domain name"),
    ],
)
def test_domain_answers(answer: str, problem: str | None) -> None:
    assert service_cli._domain(answer) == problem


@pytest.mark.parametrize(("answer", "problem"), [("x", None), ("  ", "required"), ("", "required")])
def test_required_answers(answer: str, problem: str | None) -> None:
    assert service_cli._required(answer) == problem


def test_key_file_answers(tmp_path: Path) -> None:
    (tmp_path / "keys").write_text(f"  # an indented comment\n\n{LAPTOP}\n")
    (tmp_path / "none").write_text("  # an indented comment\n")
    assert service_cli._keys_file(str(tmp_path / "keys")) is None
    assert service_cli._keys_file(f" {tmp_path / 'keys'} ") is None
    assert service_cli._keys_file(str(tmp_path / "none")) == "no keys in that file"
    assert service_cli._keys_file(str(tmp_path / "missing")) == "no such file"
    assert service_cli._keys_file(str(tmp_path)) == "no such file"
    assert service_cli._key_lines(f"  # indented\n#\n {LAPTOP}\n{PHONE}") == 2


def test_launchd_settings_belong_to_the_install_account(
    tmp_path: Path, commands: Commands, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = Account("other", os.geteuid() + 1, os.getegid() + 1)
    chowns: list[str] = []
    monkeypatch.setattr(service.os, "chown", lambda path, uid, gid: chowns.append(f"{Path(path).name}:{uid}:{gid}"))
    monkeypatch.setattr(service_cli, "find_manager", lambda: Launchd(tmp_path))
    monkeypatch.setattr(service_cli, "install_account", lambda: other)
    monkeypatch.setattr(service_cli.os, "geteuid", lambda: 0)
    commands.replies["launchctl print system/wildburrow"] = (0, "\tstate = running\n", "")
    owned = f"env:{other.uid}:{other.gid}"
    assert cli.main(["service", "install", f"--domain={DOMAIN}"]) == 0
    assert owned in chowns
    chowns.clear()
    assert cli.main(["service", "edit", "--http-port", "8080"]) == 0
    assert owned in chowns


def test_a_failing_service_manager_is_reported(
    root: Path, commands: Commands, capsys: pytest.CaptureFixture[str]
) -> None:
    commands.replies["systemctl enable --now wildburrow"] = (1, "", "Unit failed to start.")
    assert cli.main(["service", "install", f"--domain={DOMAIN}"]) == 1
    assert capsys.readouterr().err == "`systemctl enable --now wildburrow` failed: Unit failed to start.\n"
