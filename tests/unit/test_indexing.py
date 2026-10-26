import pytest

from wildburrow.config import ConfigError
from wildburrow.core.indexing import Indexing, indexed, parse


@pytest.mark.parametrize(
    ("rule", "asked", "expected"),
    [
        (Indexing.NEVER, None, False), (Indexing.NEVER, True, False), (Indexing.NEVER, False, False),
        (Indexing.OPT_IN, None, False), (Indexing.OPT_IN, True, True), (Indexing.OPT_IN, False, False),
        (Indexing.OPT_OUT, None, True), (Indexing.OPT_OUT, True, True), (Indexing.OPT_OUT, False, False),
    ],
)  # fmt: skip
def test_the_server_rule_and_the_client_choice(rule: Indexing, asked: bool | None, expected: bool) -> None:
    assert indexed(rule, asked) is expected


def test_the_rule_is_read_case_blind() -> None:
    assert parse("WILDBURROW_INDEX", " Opt-Out ") is Indexing.OPT_OUT


def test_a_rule_that_isnt_one_is_refused() -> None:
    with pytest.raises(ConfigError, match=r"^WILDBURROW_INDEX: expected one of never, opt-in, opt-out, got 'maybe'$"):
        parse("WILDBURROW_INDEX", "maybe")
