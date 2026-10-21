from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.unit.test_certs import DOMAIN, FakeIssuer, manager
from tests.unit.test_registry import FakeTunnel
from wildburrow.auth.base import Authenticator
from wildburrow.core.context import CertificateFailed, NotAllowed, ServerContext
from wildburrow.core.errors import BindRejected
from wildburrow.core.names import InvalidName, Name, allows, parse_name, parse_patterns
from wildburrow.core.types import Identity


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("any", None),
        (" ANY ", None),
        ("alice", ("alice",)),
        ("Alice, *.alice ,alice,", ("alice", "*.alice")),
        ("a.*.b", ("a.*.b",)),
    ],
)
def test_patterns(raw: str, expected: tuple[str, ...] | None) -> None:
    assert parse_patterns(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "no names given: pass the names it may claim, or any"),
        (" , ", "no names given: pass the names it may claim, or any"),
        ("alice,bad_label", "'bad_label': labels are 1-63 of a-z, 0-9 and '-', or '*' for any one label"),
        ("a..b", "'a..b': labels are"),
        ("-a", "'-a': labels are"),
    ],
)
def test_patterns_refuse_what_is_not_a_name(raw: str, message: str) -> None:
    with pytest.raises(InvalidName, match=message.replace("*", r"\*")):
        parse_patterns(raw)


def name(raw: str) -> Name:
    return parse_name(raw, DOMAIN, max_depth=5)


@pytest.mark.parametrize(
    ("patterns", "raw", "allowed"),
    [
        (None, "anything.at.all", True),
        (("alice",), "alice", True),
        (("alice",), "bob", False),
        (("alice",), "api.alice", False),
        (("*.alice",), "api.alice", True),
        (("*.alice",), "*.alice", True),
        (("*.alice",), "alice", False),
        (("*.alice",), "x.api.alice", False),
        (("alice", "*.alice"), "alice", True),
        (("a.*.b",), "a.x.b", True),
        (("a.*.b",), "a.x.c", False),
    ],
)
def test_allows(patterns: tuple[str, ...] | None, raw: str, allowed: bool) -> None:
    assert allows(patterns, name(raw)) is allowed


labels = st.lists(st.sampled_from(["a", "b"]), min_size=1, max_size=3)


@given(labels)
def test_a_name_is_always_allowed_by_itself_and_by_any(parts: list[str]) -> None:
    exact = ".".join(parts)
    assert allows((exact,), name(exact))
    assert allows(None, name(exact))


def ctx(tmp_path: Path) -> ServerContext:
    return ServerContext(DOMAIN, 5, tmp_path, Authenticator([]))


def tunnel(who: str = "alice", names: tuple[str, ...] | None = None) -> FakeTunnel:
    return FakeTunnel(Identity(who, "token", who, names))


async def test_every_name_is_bound(tmp_path: Path) -> None:
    context, mine = ctx(tmp_path), tunnel()
    assert await context.bind_all(["a", "*.a", "a"], mine, print) == [name("a"), name("*.a")]
    assert context.registry.holders() == {name("a"): mine, name("*.a"): mine}


async def test_one_name_in_the_way_binds_none_and_says_what_all_were(tmp_path: Path) -> None:
    context = ctx(tmp_path)
    await context.bind("taken", tunnel("bob"), print)
    scoped = tunnel("alice", ("alice", "*.alice", "taken"))
    with pytest.raises(BindRejected) as rejected:
        await context.bind_all(["alice", "taken", "bad_label", "other"], scoped, print)
    assert str(rejected.value) == (
        "taken is already bound by bob; "
        "'bad_label': 'bad_label' must be 1-63 of a-z, 0-9 and '-', not starting or ending with '-'; "
        "other: alice may only claim alice, *.alice, taken"
    )
    assert context.registry.names() == [name("taken")]


async def test_a_name_outside_the_tokens_names_is_refused(tmp_path: Path) -> None:
    with pytest.raises(NotAllowed, match=r"^bob: alice may only claim alice$"):
        await ctx(tmp_path).bind("bob", tunnel("alice", ("alice",)), print)


async def test_the_same_identity_moves_its_names_whatever_token_it_uses(tmp_path: Path) -> None:
    context = ctx(tmp_path)
    first, second = tunnel("alice", ("alice",)), tunnel("alice", None)
    await context.bind("alice", first, print)
    await context.bind("alice", second, print)
    assert context.registry.holder(name("alice")) is second


async def test_a_failed_certificate_releases_every_name(tmp_path: Path) -> None:
    context = ctx(tmp_path)
    context.certs = manager(tmp_path, FakeIssuer(fail=1))
    notes: list[str] = []
    with pytest.raises(CertificateFailed):
        await context.bind_all(["a", "b.a"], tunnel(), notes.append)
    assert context.registry.names() == []
    assert notes == [f"issuing a certificate for *.{DOMAIN}"]


async def test_each_certificate_is_asked_for_once(tmp_path: Path) -> None:
    context = ctx(tmp_path)
    context.certs = issuing = manager(tmp_path, issuer := FakeIssuer())
    notes: list[str] = []
    await context.bind_all(["a", "b", "*.a", "x.a"], tunnel(), notes.append)
    assert notes == [f"issuing a certificate for *.{DOMAIN}", f"issuing a certificate for *.a.{DOMAIN}"]
    assert len(issuer.calls) == 2
    await context.bind_all(["c"], tunnel(), notes.append)
    assert len(notes) == 2
    assert issuing.ready(DOMAIN)
