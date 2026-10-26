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
        "tokens": [ALICE.token], "ended": [first.id, second.id]
    }  # fmt: skip
    assert ctx.denied == {ALICE.token}
    assert written.seen == [
        ("session", "root", True),
        ("session", "alice", False),
        ("session", "alice", False),
        ("deny", ALICE.token, "root"),
    ]


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
