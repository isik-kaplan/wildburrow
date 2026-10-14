import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow.core.names import LABEL, InvalidName, Name, host_labels, parse_name

DOMAIN = "tunnel.example.com"
labels = st.from_regex(LABEL, fullmatch=True)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("myapp", Name(("myapp",))),
        ("*.foo", Name(("foo",), wildcard=True)),
        ("*.bar.foo", Name(("bar", "foo"), wildcard=True)),
        ("API.Foo", Name(("api", "foo"))),
        ("a-b.c1", Name(("a-b", "c1"))),
    ],
)
def test_valid_names(raw: str, expected: Name) -> None:
    assert parse_name(raw, DOMAIN, max_depth=5) == expected


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("*", "at least one label"),
        ("*.*.foo", "only allowed as the leftmost"),
        ("foo.*", "only allowed as the leftmost"),
        ("", "must be 1-63"),
        ("a..b", "must be 1-63"),
        ("-a", "must be 1-63"),
        ("a-", "must be 1-63"),
        ("a_b", "must be 1-63"),
        ("a" * 64, "must be 1-63"),
        ("a.b.c.d.e.f", "deeper than"),
        ("*.b.c.d.e.f", "deeper than"),
        ("\u212a", "must be ascii"),
        (".".join(["a" * 63] * 4), "longer than"),
    ],
)
def test_invalid_names(raw: str, reason: str) -> None:
    with pytest.raises(InvalidName, match=reason):
        parse_name(raw, DOMAIN, max_depth=5)


@given(st.lists(labels, min_size=1, max_size=3), st.booleans())
def test_parse_round_trips(parts: list[str], wildcard: bool) -> None:
    name = Name(tuple(parts), wildcard)
    assert parse_name(str(name), DOMAIN, max_depth=4) == name


@given(st.text())
def test_parse_accepts_only_well_formed_names(raw: str) -> None:
    try:
        name = parse_name(raw, DOMAIN, max_depth=5)
    except InvalidName:
        return
    assert all(LABEL.fullmatch(label) for label in name.labels)
    assert str(name) == raw.lower()


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        (f"a.b.{DOMAIN}", ("a", "b")),
        (f"A.{DOMAIN.upper()}", ("a",)),
        (DOMAIN, None),
        (f".{DOMAIN}", None),
        (f"a_b.{DOMAIN}", None),
        ("a.example.org", None),
        (f"a.x{DOMAIN}", None),
    ],
)
def test_host_labels(host: str, expected: tuple[str, ...] | None) -> None:
    assert host_labels(host, DOMAIN) == expected


@given(st.lists(labels, min_size=1, max_size=4))
def test_host_labels_inverts_fqdn(parts: list[str]) -> None:
    assert host_labels(Name(tuple(parts)).fqdn(DOMAIN), DOMAIN) == tuple(parts)
