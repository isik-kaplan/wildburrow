"""Every client setting, given every way it can be, and every pair of those ways against each other."""

from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.unit.test_cli_locks import home, quiet_env  # noqa: F401
from wildburrow import cli
from wildburrow.cli import client as client_cli
from wildburrow.cli import saved
from wildburrow.client.config import LOGIN, ClientConfig, config_path, read_toml, write_config, write_toml

# Each setting's two sample values: the option's arguments, the text a variable or config.toml holds, and the value
# either resolves to. The first is given the stronger way when two are given.
SAMPLES: dict[str, tuple[tuple[list[str], str, Any], tuple[list[str], str, Any]]] = {
    "server": ((["--server", "a.example.com"], "a.example.com", "a.example.com"),
               (["--server", "b.example.com"], "b.example.com", "b.example.com")),
    "token": ((["--token", "t1"], "t1", "t1"), (["--token", "t2"], "t2", "t2")),
    "ssh_port": ((["--ssh-port", "2201"], "2201", 2201), (["--ssh-port", "2202"], "2202", 2202)),
    "user": ((["--user", "u1"], "u1", "u1"), (["--user", "u2"], "u2", "u2")),
    "transport": ((["--transport", "websocket"], "websocket", "websocket"), (["--transport", "ssh"], "ssh", "ssh")),
    "auth": ((["--auth", "password"], "password", "password"), (["--auth", "key"], "key", "key")),
    "identity": ((["--identity", "/k1"], "/k1", "/k1"), (["--identity", "/k2"], "/k2", "/k2")),
    "url": ((["--url", "http://a"], "http://a", "http://a"), (["--url", "http://b"], "http://b", "http://b")),
    "reconnect": ((["--no-reconnect"], "no", False), (["--reconnect"], "yes", True)),
    "retry_delay": ((["--retry-delay", "2"], "2", 2.0), (["--retry-delay", "3"], "3", 3.0)),
    "retry_max": ((["--retry-max", "40"], "40", 40.0), (["--retry-max", "50"], "50", 50.0)),
    "local_host": ((["--local-host", "127.0.0.2"], "127.0.0.2", "127.0.0.2"),
                   (["--local-host", "127.0.0.3"], "127.0.0.3", "127.0.0.3")),
    "index": ((["--index"], "yes", True), (["--no-index"], "no", False)),
    "lock": ((["--lock", "a:x"], "a:x", ("a:x",)), (["--lock", "b:y"], "b:y", ("b:y",))),
    "lock_guest": ((["--lock-guest"], "yes", True), ([], "no", False)),
    "link": ((["--link"], "yes", True), ([], "no", False)),
    "links": ((["--links", "2"], "2", ("2",)), (["--links", "c"], "c", ("c",))),
    "link_expires": ((["--link-expires", "1h"], "1h", "1h"), (["--link-expires", "2h"], "2h", "2h")),
    "link_uses": ((["--link-uses", "any"], "any", None), (["--link-uses", "3"], "3", 3)),
    "lock_path": ((["--lock-path", "/a"], "/a", "/a"), (["--lock-path", "/b"], "/b", "/b")),
    "lock_cookie": ((["--lock-cookie", "c1"], "c1", "c1"), (["--lock-cookie", "c2"], "c2", "c2")),
    "lock_header": ((["--lock-header", "X-A"], "X-A", "X-A"), (["--lock-header", "X-B"], "X-B", "X-B")),
    "lock_user_header": ((["--lock-user-header", "X-U"], "X-U", "X-U"),
                         (["--lock-user-header", "X-V"], "X-V", "X-V")),
    "lock_expires": ((["--lock-expires", "1h"], "1h", "1h"), (["--lock-expires", "2h"], "2h", "2h")),
    "lock_confirm_links": ((["--no-lock-confirm-links"], "no", False), (["--lock-confirm-links"], "yes", True)),
    "lock_page": ((["--lock-page", "<p>a</p>"], "<p>a</p>", "<p>a</p>"),
                  (["--lock-page", "<p>b</p>"], "<p>b</p>", "<p>b</p>")),
    "lock_link_page": ((["--lock-link-page", "<p>a</p>"], "<p>a</p>", "<p>a</p>"),
                       (["--lock-link-page", "<p>b</p>"], "<p>b</p>", "<p>b</p>")),
    "lock_message_page": ((["--lock-message-page", "<p>a</p>"], "<p>a</p>", "<p>a</p>"),
                          (["--lock-message-page", "<p>b</p>"], "<p>b</p>", "<p>b</p>")),
}  # fmt: skip
OPTION, VARIABLE, FILE, SAVED = "option", "variable", "file", "config.toml"
# Every pair of ways, the stronger first.
PAIRS = [(OPTION, VARIABLE), (OPTION, FILE), (OPTION, SAVED), (VARIABLE, SAVED), (FILE, SAVED)]
# What lets a lock setting be given at all, unless it's the one being tried.
LOCKED = ["--lock", "base:pw"]


def test_every_setting_has_samples() -> None:
    assert set(SAMPLES) == set(saved.SAVED)


class Opened:
    """What connect resolved, stopped before it connects."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.found: list[tuple[Any, ClientConfig]] = []
        monkeypatch.setattr(client_cli, "_connect", self.record)

    def record(self, port: int, names: tuple[str, ...], settings: Any) -> int:
        self.found.append((settings, client_cli.reach(settings)))
        return 0

    def value(self, name: str) -> Any:
        [(settings, config)] = self.found
        if name in LOGIN:
            return getattr(config, name)
        entry = saved.SAVED[name]
        found = settings
        for step in entry.path:
            found = getattr(found, step)
        return found


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch, no_terminal: None) -> Opened:
    for entry in saved.SAVED.values():
        monkeypatch.delenv(entry.env_name, raising=False)
        monkeypatch.delenv(f"{entry.env_name}_FILE", raising=False)
    write_config(config_path(), ClientConfig("s.example.com"))
    return Opened(monkeypatch)


def give(
    name: str, way: str, sample: tuple[list[str], str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> list[str]:
    """Gives `name` its `sample` the `way` asked; the options to pass for it."""
    args, text, _ = sample
    variable = saved.SAVED[name].env_name
    if way == OPTION:
        return args
    if way == VARIABLE:
        monkeypatch.setenv(variable, text)
    elif way == FILE:
        held = tmp_path / f"{name}.txt"
        held.write_text(text + "\n")
        monkeypatch.setenv(f"{variable}_FILE", str(held))
    else:
        typed = sample[2] if name in LOGIN else text
        write_toml(config_path(), {**read_toml(config_path()), name: typed})
    return []


def run(name: str, *args: str) -> int:
    base = [] if name in LOGIN or not name.startswith(("lock_", "link")) else LOCKED
    return cli.main(["connect", "3000", "app", *base, *args])


@pytest.mark.parametrize("way", [OPTION, VARIABLE, FILE, SAVED])
@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_each_way_gives_the_setting(
    name: str, way: str, opened: Opened, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sample = SAMPLES[name][0]
    if way == OPTION and not sample[0]:
        pytest.skip("not a way this setting is given")
    assert run(name, *give(name, way, sample, monkeypatch, tmp_path)) == 0
    assert opened.value(name) == sample[2]


@pytest.mark.parametrize(("stronger", "weaker"), PAIRS)
@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_the_stronger_way_wins(
    name: str, stronger: str, weaker: str, opened: Opened, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first, second = SAMPLES[name]
    args = give(name, weaker, second, monkeypatch, tmp_path) + give(name, stronger, first, monkeypatch, tmp_path)
    assert run(name, *args) == 0
    assert opened.value(name) == first[2]


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_given_no_way_the_setting_keeps_its_default(name: str, opened: Opened) -> None:
    assert run(name) == 0
    found = opened.value(name)
    if name in LOGIN:
        assert found == getattr(ClientConfig("s.example.com"), name)
    else:
        default = saved.SAVED[name].declaration.default
        assert found == (() if isinstance(default, list) else default) or found is default


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_a_variable_and_its_file_together_are_refused(
    name: str, opened: Opened, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = SAMPLES[name][0]
    give(name, VARIABLE, sample, monkeypatch, tmp_path)
    give(name, FILE, sample, monkeypatch, tmp_path)
    assert run(name) == 2
    variable = saved.SAVED[name].env_name
    assert f"{variable} and {variable}_FILE are both set" in capsys.readouterr().err
    assert opened.found == []


# Whole command lines: any mix of the settings, each given one way or left out, each value good or not.

GOOD = {name: [first, second] for name, (first, second) in SAMPLES.items()}
BAD = {
    "ssh_port": "port", "transport": "pigeon", "auth": "pigeon", "reconnect": "maybe", "retry_delay": "soon",
    "retry_max": "-1", "index": "maybe", "lock_guest": "maybe", "link": "maybe", "link_expires": "soon",
    "link_uses": "0", "lock_confirm_links": "maybe",
}  # fmt: skip


@st.composite
def command_lines(draw: st.DrawFn) -> dict[str, tuple[str, int, bool]]:
    """For each setting chosen: the way it's given, which sample, and whether the value is a bad one instead."""
    chosen = draw(st.lists(st.sampled_from(sorted(SAMPLES)), unique=True, max_size=8))
    found = {}
    for name in chosen:
        way = draw(st.sampled_from([VARIABLE, FILE] if name in LOGIN or name == "token" else [OPTION, VARIABLE, FILE]))
        bad = name in BAD and draw(st.booleans())
        found[name] = (way, draw(st.integers(0, 1)), bad)
    return found


@settings(max_examples=400, suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
@given(line=command_lines())
def test_any_command_line_runs_with_exactly_what_it_gave_or_says_what_was_wrong(
    line: dict[str, tuple[str, int, bool]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    no_terminal: None,
) -> None:
    with monkeypatch.context() as patched:
        for entry in saved.SAVED.values():
            patched.delenv(entry.env_name, raising=False)
            patched.delenv(f"{entry.env_name}_FILE", raising=False)
        write_config(config_path(), ClientConfig("s.example.com"))
        opened = Opened(patched)
        args: list[str] = []
        for name, (way, which, bad) in line.items():
            sample = SAMPLES[name][which]
            if bad:
                # Refused values go by variable, which names itself in what it says is wrong.
                way, sample = VARIABLE, (sample[0], BAD[name], None)
            if way == OPTION and not sample[0]:
                way = VARIABLE
            args += give(name, way, sample, patched, tmp_path)
        # Every sample of `lock` locks the tunnel, which the base lock would add to; any other leaves it to the base.
        locking = [] if "lock" in line else LOCKED
        code = cli.main(["connect", "3000", "app", *locking, *args])
        err = capsys.readouterr().err
        if refused := [name for name, (_way, _which, bad) in line.items() if bad]:
            assert code == 2, err
            assert opened.found == []
            assert any(saved.SAVED[name].env_name in err for name in refused), err
            return
        assert code == 0, err
        for name, (_way, which, _bad) in line.items():
            expected = SAMPLES[name][which][2]
            assert opened.value(name) == expected, name


def test_samples_are_two_different_values() -> None:
    for name, (first, second) in SAMPLES.items():
        assert first[2] != second[2], name
