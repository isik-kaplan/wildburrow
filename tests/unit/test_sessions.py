import asyncio
import logging
import re
from pathlib import Path

import asyncssh
import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.unit.test_registry import FakeTunnel
from tests.unit.test_server import env
from wildburrow import config
from wildburrow.auth.base import Authenticator
from wildburrow.auth.token import TokenAuth, TokenSettings
from wildburrow.config import ConfigError
from wildburrow.core.context import ServerContext
from wildburrow.core.names import parse_name
from wildburrow.core.sessions import (
    EXPIRED,
    GRACE_SECONDS,
    LEVELS,
    Admins,
    Level,
    Policy,
    Session,
    Sessions,
    describe,
    level,
    same,
)
from wildburrow.core.types import Identity, Peer
from wildburrow.server import Server

ALICE = Identity("alice", "token", "signed:alice", ("alice",), 2_000_000_000, "3f9a0c4e1b2d7a65")
BOB = Identity("bob", "token", "signed:bob")
LAPTOP = Identity("laptop", "key", "SHA256:laptop")
PHONE = Identity("phone", "key", "SHA256:phone")
PEER = Peer("203.0.113.4", 5)
AUTH = ("key", "password", "token")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("none", Level.NONE), ("own", Level.OWN), (" Admins ", Level.ADMINS), ("ALL", Level.ALL)],
)
def test_levels(raw: str, expected: Level) -> None:
    assert level("X", raw) is expected


def test_levels_are_ordered() -> None:
    assert list(LEVELS.values()) == sorted(LEVELS.values())
    assert list(LEVELS) == ["none", "own", "admins", "all"]


@pytest.mark.parametrize("raw", ["", "some", "owner"])
def test_unknown_levels(raw: str) -> None:
    with pytest.raises(ConfigError, match=f"^WILDBURROW_SEE: expected one of none, own, admins, all, got {raw!r}$"):
        level("WILDBURROW_SEE", raw)


def test_same_identity() -> None:
    assert same(ALICE, Identity("alice", "token", "signed:alice"))
    assert not same(ALICE, BOB)
    assert not same(LAPTOP, Identity("laptop", "token", "SHA256:laptop"))
    assert same(Identity("a", "password", "a"), Identity("b", "password", "b"))
    assert not same(Identity("a", "password", "a"), Identity("a", "key", "a"))


def admins(*rules: str, signers: tuple[str, ...] = ()) -> Admins:
    return Admins.parse("WILDBURROW_ADMINS", rules, AUTH, signers)


@pytest.mark.parametrize(
    ("rules", "members"),
    [
        (("none",), set()),
        ((" none ",), set()),
        (("all",), {"alice", "bob", "laptop", "phone", "pw"}),
        (("key", "all"), {"alice", "bob", "laptop", "phone", "pw"}),
        (("key",), {"laptop", "phone"}),
        (("token",), {"alice", "bob"}),
        (("password",), {"pw"}),
        (("key", "password"), {"laptop", "phone", "pw"}),
        (("signers",), {"phone"}),
        (("token:alice",), {"alice"}),
        (("token:signed:bob",), {"bob"}),
        (("key:SHA256:laptop",), {"laptop"}),
        (("key:phone",), {"phone"}),
        (("key:alice",), set()),
        (("signers", "token:bob"), {"phone", "bob"}),
    ],
)
def test_admin_rules(rules: tuple[str, ...], members: set[str]) -> None:
    found = admins(*rules, signers=("SHA256:phone", "signed:alice"))
    everyone = [ALICE, BOB, LAPTOP, PHONE, Identity("pw", "password", "pw")]
    assert {identity.name for identity in everyone if identity in found} == members


def test_no_admins_by_default() -> None:
    assert LAPTOP not in Admins()
    assert LAPTOP not in Policy().admins


@pytest.mark.parametrize(
    ("rules", "message"),
    [
        (("none", "key"), "WILDBURROW_ADMINS: none can't be combined with other rules"),
        (("ldap",), "WILDBURROW_ADMINS: 'ldap' is neither a rule nor one of the auth methods; expected none, all, "
                    "signers, key, password, token"),
        (("ldap:x",), "WILDBURROW_ADMINS: 'ldap:x' is neither a rule"),
        (("password:bob",), "WILDBURROW_ADMINS: 'password:bob' can't name one person; anyone with the password"),
        (("token:",), "WILDBURROW_ADMINS: 'token:' can't name one person"),
    ],
)  # fmt: skip
def test_admin_rules_that_cant_work(rules: tuple[str, ...], message: str) -> None:
    with pytest.raises(ConfigError, match="^" + re.escape(message)):
        admins(*rules)


def test_admin_rules_name_methods_the_server_runs() -> None:
    with pytest.raises(ConfigError, match="'token' is neither"):
        Admins.parse("A", ("token",), ("key",), ())
    assert LAPTOP in Admins.parse("A", ("signers",), (), ("SHA256:laptop",))


ADMIN = Identity("root", "key", "SHA256:root")
OTHER_ADMIN = Identity("ops", "key", "SHA256:ops")
USER = Identity("user", "token", "signed:user")
OTHER_USER = Identity("guest", "token", "signed:guest")
POLICY_ADMINS = Admins(exact=frozenset({("key", "root"), ("key", "ops")}))

# Who reaches whom at each level: yourself, another admin, someone who isn't.
REACH = {
    Level.NONE: {(ADMIN, ADMIN): False, (USER, USER): False, (ADMIN, USER): False},
    Level.OWN: {(ADMIN, ADMIN): True, (USER, USER): True, (ADMIN, USER): False, (ADMIN, OTHER_ADMIN): False},
    Level.ADMINS: {
        (ADMIN, ADMIN): True,
        (USER, USER): True,
        (ADMIN, USER): True,
        (ADMIN, OTHER_ADMIN): False,
        (USER, OTHER_USER): False,
        (USER, ADMIN): False,
    },
    Level.ALL: {
        (ADMIN, ADMIN): True,
        (ADMIN, USER): True,
        (ADMIN, OTHER_ADMIN): True,
        (USER, OTHER_USER): False,
        (USER, ADMIN): False,
    },
}


@pytest.mark.parametrize(
    ("reach", "actor", "target", "expected"),
    [(reach, actor, target, expected) for reach, pairs in REACH.items() for (actor, target), expected in pairs.items()],
)
def test_who_reaches_whom(reach: Level, actor: Identity, target: Identity, expected: bool) -> None:
    assert Policy(POLICY_ADMINS, see=reach, kick=reach).kicks(actor, target) is expected
    assert Policy(POLICY_ADMINS, see=reach, kick=Level.NONE).sees(actor, target) is expected
    assert Policy(POLICY_ADMINS, see=Level.ALL, kick=reach).kicks(actor, target) is expected


@given(see=st.sampled_from(Level), kick=st.sampled_from(Level))
def test_ending_never_reaches_further_than_seeing(see: Level, kick: Level) -> None:
    if kick > see:
        with pytest.raises(ConfigError, match=r"^WILDBURROW_KICK reaches further than WILDBURROW_SEE, and no one"):
            Policy(see=see, kick=kick)
    else:
        assert Policy(see=see, kick=kick).kick is kick


def test_the_default_policy() -> None:
    assert Policy() == Policy(Admins(), Level.OWN, Level.OWN)


class Ended:
    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.called = asyncio.Event()

    def __call__(self, reason: str) -> None:
        self.reasons.append(reason)
        self.called.set()


async def test_sessions_are_opened_listed_and_closed() -> None:
    sessions = Sessions(clock=lambda: 1234.9)
    first = sessions.open(LAPTOP, "ssh", PEER, Ended())
    second = sessions.open(ALICE.__replace__(expires=None), "websocket", PEER, Ended())
    assert (first.identity, first.transport, first.peer, first.since, first.timer) == (LAPTOP, "ssh", PEER, 1234, None)
    assert re.fullmatch("[0-9a-f]{12}", first.id)
    assert first.id != second.id
    assert list(sessions) == [first, second]
    for session in sessions:
        sessions.close(session)
    assert list(sessions) == []
    sessions.close(first)


async def test_a_session_ends_when_its_credential_expires() -> None:
    now = 1_000_000.0
    sessions = Sessions(clock=lambda: now)
    ended = Ended()
    session = sessions.open(ALICE.__replace__(expires=int(now) - GRACE_SECONDS), "websocket", PEER, ended)
    async with asyncio.timeout(1):
        await ended.called.wait()
    assert ended.reasons == [EXPIRED]
    assert session.timer is not None


async def test_the_expiry_waits_out_the_grace() -> None:
    now = 1_000_000.0
    loop = asyncio.get_running_loop()
    sessions = Sessions(clock=lambda: now)
    session = sessions.open(ALICE.__replace__(expires=int(now) + 30), "websocket", PEER, Ended())
    assert session.timer is not None
    assert session.timer.when() - loop.time() == pytest.approx(30 + GRACE_SECONDS, abs=1)
    late = sessions.open(ALICE.__replace__(expires=int(now) - 3600), "websocket", PEER, Ended())
    assert late.timer is not None
    assert late.timer.when() <= loop.time()


async def test_closing_a_session_stops_its_expiry() -> None:
    now = 1_000_000.0
    sessions = Sessions(clock=lambda: now)
    ended = Ended()
    session = sessions.open(ALICE.__replace__(expires=int(now) - GRACE_SECONDS), "websocket", PEER, ended)
    sessions.close(session)
    await asyncio.sleep(0.01)
    assert ended.reasons == []
    assert session.timer is not None
    assert session.timer.cancelled()


def session(identity: Identity, transport: str = "websocket", id: str = "s") -> Session:
    return Session(id, identity, transport, PEER, 100, Ended())


def test_describing_a_session() -> None:
    entry = describe(session(ALICE, "ssh", "a1"), ["alice"], BOB, admin=False)
    assert entry == {
        "id": "a1",
        "who": "alice",
        "via": "token",
        "transport": "ssh",
        "names": ["alice"],
        "since": 100,
        "expires": 2_000_000_000,
        "token": "3f9a0c4e1b2d7a65",
        "yours": False,
    }
    assert describe(session(ALICE), [], BOB, admin=True)["from"] == PEER.host
    mine = describe(session(ALICE), [], Identity("alice", "token", "signed:alice"), admin=False)
    assert (mine["yours"], mine["from"]) == (True, PEER.host)


def context(tmp_path: Path, policy: Policy) -> ServerContext:
    return ServerContext("example.com", 5, tmp_path, Authenticator([]), policy=policy)


def opened(ctx: ServerContext, identity: Identity, *names: str) -> tuple[Session, Ended]:
    ended = Ended()
    session = ctx.sessions.open(identity, "websocket", PEER, ended)
    for raw in names:
        ctx.registry.bind(parse_name(raw, ctx.domain, ctx.max_depth), FakeTunnel(identity, session))
    return session, ended


async def test_listing_shows_only_what_the_policy_lets_through(tmp_path: Path) -> None:
    ctx = context(tmp_path, Policy(POLICY_ADMINS, see=Level.ADMINS, kick=Level.ADMINS))
    admin, _ = opened(ctx, ADMIN)
    user, _ = opened(ctx, USER, "user", "*.user")
    other_admin, _ = opened(ctx, OTHER_ADMIN, "ops")
    second_user, _ = opened(ctx, USER)
    ctx.registry.bind(parse_name("loose", ctx.domain, 5), FakeTunnel(USER))
    assert [entry["id"] for entry in ctx.listing(admin)] == [user.id, second_user.id]
    assert ctx.listing(admin)[0]["names"] == ["user", "*.user"]
    assert ctx.listing(admin)[0]["from"] == PEER.host
    assert [entry["id"] for entry in ctx.listing(user)] == [second_user.id]
    assert ctx.listing(other_admin) == [
        describe(user, ["user", "*.user"], OTHER_ADMIN, True),
        describe(second_user, [], OTHER_ADMIN, True),
    ]


async def test_kicking_by_session_name_or_identity(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    ctx = context(tmp_path, Policy(POLICY_ADMINS, see=Level.ALL, kick=Level.ADMINS))
    admin, admin_ended = opened(ctx, ADMIN)
    user, user_ended = opened(ctx, USER, "user")
    second, second_ended = opened(ctx, USER)
    other_admin, other_ended = opened(ctx, OTHER_ADMIN, "ops")
    assert ctx.kick(admin, {"session": user.id}) == {
        "sessions": [describe(user, ["user"], ADMIN, True)],
        "refused": [],
    }
    assert user_ended.reasons == ["ended by root"]
    assert ("wildburrow.core.context", logging.INFO, f"root ended session {user.id} of user") in caplog.record_tuples
    assert ctx.kick(admin, {"name": "ops"}) == {"sessions": [], "refused": [other_admin.id]}
    assert ctx.kick(admin, {"name": "USER"})["sessions"][0]["id"] == user.id
    assert ctx.kick(admin, {"who": "user"})["sessions"] == [
        describe(user, ["user"], ADMIN, True),
        describe(second, [], ADMIN, True),
    ]
    assert ctx.kick(admin, {"who": "root"}) == {"sessions": [], "refused": []}
    assert ctx.kick(admin, {"session": admin.id}) == {"sessions": [], "refused": []}
    assert (admin_ended.reasons, other_ended.reasons) == ([], [])
    assert second_ended.reasons == ["ended by root"]


@pytest.mark.parametrize("request_", [{"name": "nobody"}, {"name": "bad_name"}, {"name": "loose"}, {"session": "x"}])
async def test_kicking_what_isnt_there(tmp_path: Path, request_: dict[str, str]) -> None:
    ctx = context(tmp_path, Policy(POLICY_ADMINS, see=Level.ALL, kick=Level.ALL))
    admin, _ = opened(ctx, ADMIN)
    opened(ctx, USER, "user")
    ctx.registry.bind(parse_name("loose", ctx.domain, 5), FakeTunnel(USER))
    assert ctx.kick(admin, request_) == {"sessions": [], "refused": []}


async def test_kicking_needs_a_target(tmp_path: Path) -> None:
    ctx = context(tmp_path, Policy())
    admin, _ = opened(ctx, ADMIN)
    with pytest.raises(KeyError):
        ctx.kick(admin, {})


async def test_what_cant_be_seen_cant_be_kicked(tmp_path: Path) -> None:
    ctx = context(tmp_path, Policy(POLICY_ADMINS, see=Level.OWN, kick=Level.OWN))
    admin, _ = opened(ctx, ADMIN)
    user, ended = opened(ctx, USER)
    mine, mine_ended = opened(ctx, ADMIN)
    assert ctx.kick(admin, {"session": user.id}) == {"sessions": [], "refused": []}
    assert ctx.kick(admin, {"session": mine.id})["sessions"][0]["yours"] is True
    assert (ended.reasons, mine_ended.reasons) == ([], ["ended by root"])


def key_line() -> tuple[str, str]:
    key = asyncssh.generate_private_key("ssh-ed25519")
    return key.export_public_key().decode(), key.get_fingerprint()


def test_the_server_builds_its_policy(tmp_path: Path) -> None:
    line, fingerprint = key_line()
    values = env(
        tmp_path,
        AUTH="key,token",
        AUTH_KEY_AUTHORIZED_KEYS=line,
        AUTH_TOKEN_SIGNERS=line,
        TRANSPORTS="websocket",
        SEE="admins",
        KICK="Own",
    )
    policy = Server(config.load(config.ServerSettings, values, config.PREFIX), values).ctx.policy
    assert (policy.see, policy.kick) == (Level.ADMINS, Level.OWN)
    assert Identity("me", "key", fingerprint) in policy.admins
    assert Identity("me", "key", "SHA256:other") not in policy.admins


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"SEE": "most"}, "WILDBURROW_SEE: expected one of"),
        ({"KICK": "most"}, "WILDBURROW_KICK: expected one of"),
        ({"SEE": "own", "KICK": "all"}, "WILDBURROW_KICK reaches further than WILDBURROW_SEE"),
        ({"ADMINS": "token"}, "WILDBURROW_ADMINS: 'token' is neither"),
    ],
)
def test_the_server_refuses_a_policy_that_cant_work(tmp_path: Path, overrides: dict[str, str], message: str) -> None:
    values = env(tmp_path, **overrides)
    with pytest.raises(ConfigError, match="^" + re.escape(message)):
        Server(config.load(config.ServerSettings, values, config.PREFIX), values)


def test_signers_come_from_the_token_plugin() -> None:
    line, fingerprint = key_line()
    other, other_fingerprint = key_line()
    token = TokenAuth(TokenSettings(signers=f"{line}\n{other}"))
    assert token.signers == {fingerprint, other_fingerprint}
    assert Authenticator([token, object()]).signers() == {fingerprint, other_fingerprint}  # type: ignore[list-item]
    assert Authenticator([]).signers() == frozenset()
