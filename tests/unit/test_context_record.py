import dataclasses
import hashlib
from pathlib import Path
from typing import Any

import pytest

from tests.unit.test_auth import Fixed
from tests.unit.test_locks import Changes, bound, locked_tunnel, spec
from tests.unit.test_registry import FakeTunnel
from tests.unit.test_sessions import ADMIN, ALICE, BOB, LAPTOP, PEER, POLICY_ADMINS
from wildburrow.auth.base import Authenticator
from wildburrow.core.context import BindRejected, ServerContext
from wildburrow.core.locks import Entry
from wildburrow.core.sessions import Policy, Session
from wildburrow.core.types import Identity, PasswordCredential, TokenCredential


class Written:
    """What the server context writes in its record, without the objects it hands over whole."""

    def __init__(self, ctx: ServerContext, monkeypatch: pytest.MonkeyPatch) -> None:
        self.seen: list[tuple[Any, ...]] = []
        for name in (
            "auth",
            "session_opened",
            "session_closed",
            "deny",
            "deny_name",
            "register",
            "tunnel_opened",
            "tunnel_rejected",
            "lock_made",
            "credential",
        ):
            monkeypatch.setattr(ctx.record, name, getattr(self, name))

    def auth(self, transport: str, method: str, peer: object, identity: Identity | None, reason: str | None) -> None:
        self.seen.append(("auth", method, identity and identity.name, reason))

    def session_opened(self, session: Session, admin: bool, client: dict[str, Any]) -> None:
        self.seen.append(("session", session.identity.name, admin))

    def session_closed(self, session: Session, reason: str | None, command: int | None = None) -> None:
        self.seen.append(("closed", session.identity.name, reason, command))

    def deny(self, token: str, by: Identity) -> None:
        self.seen.append(("deny", token, by.name))

    def deny_name(self, name: str, before: int, by: Identity) -> None:
        self.seen.append(("deny-name", name, before, by.name))

    def register(self, token: str, name: str, names: list[str] | None, expires: int | None, issued: int) -> None:
        self.seen.append(("register", token, name, names, expires, issued))

    def tunnel_opened(self, session: Session, lock: object, indexed: bool, urls: dict[str, str]) -> int:
        self.seen.append(("opened", session.id, indexed, urls))
        return 7

    def tunnel_rejected(self, session: Session, names: list[str], reason: str) -> None:
        self.seen.append(("rejected", session.id, names, reason))

    def lock_made(self, lock: object, identity: Identity, settings: dict[str, Any]) -> None:
        self.seen.append(("lock", identity.name, settings))

    def credential(self, lock: object, entry: Entry, command: int | None = None) -> None:
        self.seen.append(("credential", entry.label, command))


def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *providers: Fixed) -> tuple[ServerContext, Written]:
    ctx = ServerContext("example.com", 5, tmp_path, Authenticator(providers), policy=Policy(POLICY_ADMINS))
    return ctx, Written(ctx, monkeypatch)


def session(ctx: ServerContext, identity: Identity) -> Session:
    return ctx.open_session(identity, "websocket", PEER, lambda reason: None, {})


async def test_logins_are_recorded_with_why_they_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    alice = Fixed((TokenCredential,), ALICE)
    ctx, written = context(tmp_path, monkeypatch, alice, Fixed((PasswordCredential,), None))
    assert await ctx.authenticate("websocket", TokenCredential("t"), PEER) == ALICE
    assert await ctx.authenticate("websocket", PasswordCredential("a", "b"), PEER) is None
    ctx.deny(session(ctx, ADMIN), [ALICE.token or ""])
    assert await ctx.authenticate("websocket", TokenCredential("t"), PEER) is None
    assert [seen for seen in written.seen if seen[0] == "auth"] == [
        ("auth", "token", "alice", None),
        ("auth", "password", None, "refused"),
        ("auth", "token", None, "denied"),
    ]


async def test_a_denial_ends_the_tokens_sessions_and_says_which(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, written = context(tmp_path, monkeypatch)
    admin, first, second = session(ctx, ADMIN), session(ctx, ALICE), session(ctx, ALICE)
    assert ctx.deny(admin, [ALICE.token or "", ALICE.token or ""]) == {
        "tokens": [ALICE.token], "ended": [first.id, second.id], "memory": True
    }  # fmt: skip
    assert ctx.denied == {ALICE.token}
    assert written.seen == [
        ("session", "root", True),
        ("session", "alice", False),
        ("session", "alice", False),
        ("deny", ALICE.token, "root"),
    ]


async def test_only_a_token_id_can_be_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, written = context(tmp_path, monkeypatch, Fixed((PasswordCredential,), LAPTOP))
    admin = session(ctx, ADMIN)
    # A key or password login's token is "", so denying it would have locked every one of them out.
    for bad in ("", "t", "3F9A0C4E1B2D7A65", "3f9a0c4e1b2d7a6", "3f9a0c4e1b2d7a65x", "3f9a0c4e1b2d7a6g", "X" * 16):
        assert ctx.deny(admin, [ALICE.token or "", bad]) == {
            "error": f"not a token id: {bad!r}; `wildburrow tokens` lists them"
        }  # fmt: skip
    assert ctx.deny(admin, ["t", "u"]) == {"error": "not a token id: 't', 'u'; `wildburrow tokens` lists them"}
    assert ctx.deny(admin, [], names=["alice", ""]) == {"error": "a name to deny can't be empty"}
    assert (ctx.denied, ctx.denied_names) == (set(), {})
    assert admin.reason is None
    assert await ctx.authenticate("websocket", PasswordCredential("a", "b"), PEER) == LAPTOP
    assert [seen for seen in written.seen if seen[0] in ("deny", "deny-name")] == []


async def test_a_name_denied_refuses_its_tokens_minted_before_and_ends_their_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = 1_900_000_000
    monkeypatch.setattr("wildburrow.core.context.time.time", lambda: now)
    old = dataclasses.replace(ALICE, issued=now - 3600)
    # Minted a little after, on a clock running behind: still refused, within the minute's margin.
    skewed = dataclasses.replace(ALICE, token="0123456789abcdef", issued=now + 59)
    new = dataclasses.replace(ALICE, token="fedcba9876543210", issued=now + 60)
    same_name_by_key = Identity("alice", "key", "SHA256:alice")
    unsigned = Identity("alice", "token", "alice-hash")
    tokens = {"old": old, "skewed": skewed, "new": new, "key": same_name_by_key, "unsigned": unsigned}
    providers = [Fixed((TokenCredential,), identity) for identity in tokens.values()]
    ctx = ServerContext("example.com", 5, tmp_path, Authenticator(providers[:1]), policy=Policy(POLICY_ADMINS))
    written = Written(ctx, monkeypatch)
    admin = session(ctx, ADMIN)
    opened = {label: session(ctx, identity) for label, identity in tokens.items()}
    other = session(ctx, dataclasses.replace(BOB, token="00000000000000aa", issued=now - 3600))
    answer = ctx.deny(admin, [], 3, ["alice", "alice"])
    assert answer == {
        "tokens": [], "ended": [opened["old"].id, opened["skewed"].id], "memory": True, "names": ["alice"],
        "before": now + 60,
    }  # fmt: skip
    assert ctx.denied_names == {"alice": now + 60}
    assert [label for label, each in opened.items() if each.reason] == ["old", "skewed"]
    assert other.reason is None
    assert ("deny-name", "alice", now + 60, "root") in written.seen
    for label, identity in tokens.items():
        ctx.authenticator = Authenticator([Fixed((TokenCredential,), identity)])
        refused = await ctx.authenticate("websocket", TokenCredential("t"), PEER) is None
        assert refused == (label in ("old", "skewed")), label


async def test_registering_a_token_takes_only_what_a_token_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, written = context(tmp_path, monkeypatch)
    admin, alice = session(ctx, ADMIN), session(ctx, ALICE)
    grant = {"id": "3f9a0c4e1b2d7a65", "name": "bob", "names": ["bob"], "expires": 2_000_000_000, "issued": 1}
    assert ctx.register(alice, grant) == {"error": "only an admin can register tokens"}
    assert ctx.register(admin, grant) == {"id": grant["id"], "memory": True}
    assert ctx.register(admin, {**grant, "names": None, "expires": None}) == {"id": grant["id"], "memory": True}
    assert [seen for seen in written.seen if seen[0] == "register"] == [
        ("register", grant["id"], "bob", ["bob"], 2_000_000_000, 1),
        ("register", grant["id"], "bob", None, None, 1),
    ]
    for wrong, error in [
        ({"id": ""}, "not a token id: ''"),
        ({"id": None}, "not a token id: None"),
        ({"name": ""}, "a token needs a name"),
        ({"name": 3}, "a token needs a name"),
        ({"names": "bob"}, "a token's names are a list of names, or null for any"),
        ({"names": [3]}, "a token's names are a list of names, or null for any"),
        ({"issued": None}, "a token's issued and expires are unix seconds"),
        ({"issued": True}, "a token's issued and expires are unix seconds"),
        ({"expires": "soon"}, "a token's issued and expires are unix seconds"),
    ]:
        assert ctx.register(admin, {**grant, **wrong}) == {"error": error}


async def test_only_an_admin_lists_tokens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, _written = context(tmp_path, monkeypatch)
    rows = [
        {"id": "3f9a0c4e1b2d7a65", "name": "alice", "denied": None},
        {"id": "name:bob", "name": "bob", "denied": 7},
    ]

    async def listed() -> list[dict[str, Any]]:
        return rows

    monkeypatch.setattr(ctx.record, "tokens", listed)
    assert await ctx.token_listing(session(ctx, ALICE)) == {"error": "only an admin can list tokens"}
    assert await ctx.token_listing(session(ctx, ADMIN)) == {
        "tokens": rows[:1], "denied_names": {"bob": 7}, "memory": True
    }  # fmt: skip


async def test_tunnels_are_recorded_for_a_session_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, written = context(tmp_path, monkeypatch)
    opened = session(ctx, ALICE)
    tunnel = FakeTunnel(ALICE, opened, index=True)
    await ctx.bind_all(["alice"], tunnel, lambda text: None)
    with pytest.raises(BindRejected) as rejected:
        await ctx.bind_all(["-bad", "alice"], FakeTunnel(ALICE, opened), lambda text: None)
    await ctx.bind_all(["root"], FakeTunnel(ADMIN), lambda text: None)
    with pytest.raises(BindRejected):
        await ctx.bind_all(["-bad"], FakeTunnel(ADMIN), lambda text: None)
    assert tunnel.records == [7]
    assert written.seen[1:] == [
        ("opened", opened.id, True, {"alice": "http://alice.example.com"}),
        ("rejected", opened.id, ["-bad", "alice"], str(rejected.value)),
    ]


async def test_a_lock_is_recorded_with_its_own_pages_by_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, written = context(tmp_path, monkeypatch)
    ctx.lock(FakeTunnel(ALICE), ["foo"], spec(settings={"page": "<p>$title</p>"}), Changes())
    [(_, who, settings)] = written.seen
    assert who == "alice"
    assert settings["page"] == hashlib.sha256(b"<p>$title</p>").hexdigest()
    assert settings["link_page"] == ""


async def test_sessions_ended_by_a_command_are_recorded_as_ended_by_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, written = context(tmp_path, monkeypatch)
    admin, kicked, denied, left = session(ctx, ADMIN), session(ctx, LAPTOP), session(ctx, ALICE), session(ctx, BOB)
    ctx.kick(admin, {"session": kicked.id}, 4)
    ctx.deny(admin, [ALICE.token or ""], 5)
    for each in (kicked, denied, left):
        ctx.close_session(each)
    assert [seen for seen in written.seen if seen[0] == "closed"] == [
        ("closed", "laptop", "ended by root", 4),
        ("closed", "alice", "its token was denied by root", 5),
        ("closed", "bob", None, None),
    ]


async def test_a_minted_link_is_recorded_with_the_command_that_minted_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, written = context(tmp_path, monkeypatch)
    tunnel = locked_tunnel(ALICE)
    ctx.lock(tunnel, ["foo"], spec(), Changes())
    bound(ctx, tunnel, "foo")
    written.seen.clear()
    assert ctx.mint(ALICE, {"url": "foo.example.com", "label": "bob"}, 6)["label"] == "bob"
    assert written.seen[-1] == ("credential", "bob", 6)
