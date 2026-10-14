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
        ({}, "missing required setting\\(s\\): X_REQUIRED"),
        ({"X_REQUIRED": "r", "X_FLAG": "maybe"}, "X_FLAG: expected one of"),
        ({"X_REQUIRED": "r", "X_COUNT": "1.5"}, "X_COUNT: expected an integer, got '1.5'"),
    ],
)
def test_errors(env: dict[str, str], message: str) -> None:
    with pytest.raises(config.ConfigError, match=message):
        config.load(Example, env, "X_")


@given(st.lists(st.from_regex(r"[a-z0-9-]{1,10}", fullmatch=True), max_size=5))
def test_tuple_round_trip(items: list[str]) -> None:
    loaded = config.load(Example, {"X_REQUIRED": "", "X_ITEMS": ",".join(items)}, "X_")
    assert loaded.items == tuple(items)


def test_server_settings_need_a_domain() -> None:
    with pytest.raises(config.ConfigError, match=f"{config.PREFIX}DOMAIN"):
        config.load(config.ServerSettings, {}, config.PREFIX)
