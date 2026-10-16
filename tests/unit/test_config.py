from dataclasses import dataclass
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow import config


@dataclass(frozen=True)
class Example:
    required: str
    flag: bool = False
    count: int = 1
    items: tuple[str, ...] = ()
    path: Path = Path("/default")


def test_defaults_and_conversions() -> None:
    env = {"X_REQUIRED": "r", "X_FLAG": "Yes", "X_COUNT": "-3", "X_ITEMS": " a, ,b ", "X_PATH": "/data", "OTHER": "1"}
    assert config.load(Example, env, "X_") == Example("r", True, -3, ("a", "b"), Path("/data"))
    assert config.load(Example, {"X_REQUIRED": "r"}, "X_") == Example("r")


@pytest.mark.parametrize("raw", sorted(config.FALSE | {v.upper() for v in config.FALSE}))
def test_false_values(raw: str) -> None:
    assert config.load(Example, {"X_REQUIRED": "", "X_FLAG": raw}, "X_").flag is False


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({}, "missing required setting(s): X_REQUIRED"),
        (
            {"X_REQUIRED": "r", "X_FLAG": "maybe"},
            f"X_FLAG: expected one of {sorted(config.TRUE | config.FALSE)}, got 'maybe'",
        ),
        ({"X_REQUIRED": "r", "X_COUNT": "1.5"}, "X_COUNT: expected an integer, got '1.5'"),
    ],
)
def test_errors(env: dict[str, str], message: str) -> None:
    with pytest.raises(config.ConfigError) as error:
        config.load(Example, env, "X_")
    assert str(error.value) == message


@dataclass(frozen=True)
class TwoRequired:
    first: str
    second: str


def test_every_missing_setting_is_named() -> None:
    with pytest.raises(config.ConfigError, match=r"^missing required setting\(s\): X_FIRST, X_SECOND$"):
        config.load(TwoRequired, {}, "X_")


@given(st.lists(st.from_regex(r"[a-z0-9-]{1,10}", fullmatch=True), max_size=5))
def test_tuple_round_trip(items: list[str]) -> None:
    loaded = config.load(Example, {"X_REQUIRED": "", "X_ITEMS": ",".join(items)}, "X_")
    assert loaded.items == tuple(items)


def test_server_settings_need_a_domain() -> None:
    with pytest.raises(config.ConfigError, match=f"{config.PREFIX}DOMAIN"):
        config.load(config.ServerSettings, {}, config.PREFIX)


def test_settings_can_be_read_from_files(tmp_path: Path) -> None:
    (tmp_path / "required").write_text("line one\nline two\n")
    (tmp_path / "count").write_text("7\n")
    env = {"X_REQUIRED_FILE": str(tmp_path / "required"), "X_COUNT_FILE": str(tmp_path / "count")}
    assert config.load(Example, env, "X_") == Example("line one\nline two", count=7)


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"X_REQUIRED": "r", "X_REQUIRED_FILE": "/x"}, "set X_REQUIRED or X_REQUIRED_FILE, not both"),
        ({"X_REQUIRED_FILE": "/nonexistent/value"}, "X_REQUIRED_FILE: .*No such file"),
    ],
)
def test_file_errors(env: dict[str, str], message: str) -> None:
    with pytest.raises(config.ConfigError, match=message):
        config.load(Example, env, "X_")


def test_data_dir_expands_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = config.load(config.ServerSettings, {"WILDBURROW_DOMAIN": "d"}, config.PREFIX)
    assert settings.data_dir == tmp_path / ".local" / "state" / "wildburrow"
    settings = config.load(
        config.ServerSettings, {"WILDBURROW_DOMAIN": "d", "WILDBURROW_DATA_DIR": "~/x"}, config.PREFIX
    )
    assert settings.data_dir == tmp_path / "x"


def test_data_dir_is_required_without_a_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOME")
    monkeypatch.setattr(Path, "expanduser", raise_no_home)
    with pytest.raises(config.ConfigError, match="WILDBURROW_DATA_DIR is required"):
        config.load(config.ServerSettings, {"WILDBURROW_DOMAIN": "d"}, config.PREFIX)


def raise_no_home(self: Path) -> Path:
    raise RuntimeError("Could not determine home directory.")
