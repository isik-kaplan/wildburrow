from dataclasses import dataclass

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow.core.names import Name
from wildburrow.core.registry import NameTaken, Registry
from wildburrow.core.types import Identity

label = st.sampled_from(["a", "b", "c"])
names = st.lists(
    st.tuples(st.lists(label, min_size=1, max_size=3), st.booleans()), unique_by=lambda n: (tuple(n[0]), n[1])
)


@dataclass(eq=False)
class FakeTunnel:
    identity: Identity

    async def open_stream(self, peer):
        raise NotImplementedError


def tunnel(name: str = "laptop") -> FakeTunnel:
    return FakeTunnel(Identity(name, "key"))


def test_exact_and_wildcard_resolution() -> None:
    registry = Registry()
    wildcard, exact, solo = tunnel(), tunnel(), tunnel()
    registry.bind(Name(("foo",), wildcard=True), wildcard)
    registry.bind(Name(("api", "foo")), exact)
    registry.bind(Name(("solo",)), solo)
    assert registry.resolve(("auth", "foo")) is wildcard
    assert registry.resolve(("api", "foo")) is exact
    assert registry.resolve(("solo",)) is solo
    assert registry.resolve(("foo",)) is None
    assert registry.resolve(("x", "api", "foo")) is None
    assert registry.resolve(("x", "solo")) is None


def test_taken_name_names_the_holder() -> None:
    registry = Registry()
    holder = tunnel("alice")
    registry.bind(Name(("foo",), wildcard=True), holder)
    with pytest.raises(NameTaken, match=r"^\*\.foo is already bound by alice$"):
        registry.bind(Name(("foo",), wildcard=True), tunnel("bob"))
    assert registry.resolve(("x", "foo")) is holder


def test_only_the_holder_can_unbind() -> None:
    registry = Registry()
    holder, other = tunnel(), tunnel()
    name = Name(("app",))
    registry.bind(name, holder)
    registry.unbind(name, other)
    assert registry.resolve(("app",)) is holder
    registry.unbind(name, holder)
    assert registry.resolve(("app",)) is None
    registry.unbind(name, holder)


@given(
    st.lists(
        st.tuples(st.lists(label, min_size=1, max_size=3), st.booleans()), unique_by=lambda n: (tuple(n[0]), n[1])
    ),
    st.lists(label, min_size=1, max_size=4),
)
def test_resolution_matches_certificate_semantics(bound: list[tuple[list[str], bool]], host: list[str]) -> None:
    registry = Registry()
    tunnels = {}
    for parts, wildcard in bound:
        name = Name(tuple(parts), wildcard)
        tunnels[name] = tunnel()
        registry.bind(name, tunnels[name])

    covering = [n for n in tunnels if n.labels == tuple(host[1:] if n.wildcard else host)]
    exact = [n for n in covering if not n.wildcard]
    expected = exact or covering
    resolved = registry.resolve(tuple(host))
    assert (resolved is None) == (not expected)
    if expected:
        assert resolved is tunnels[expected[0]]
