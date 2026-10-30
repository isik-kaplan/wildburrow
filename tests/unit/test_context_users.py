import dataclasses
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from argon2 import PasswordHasher

from tests.unit.test_auth import Fixed
from tests.unit.test_sessions import ADMIN, PEER, POLICY_ADMINS
from tests.unit.test_store import Clock
from tests.unit.test_users import new_key
from wildburrow.auth.base import Authenticator
from wildburrow.core.context import NOT_A_USER, ServerContext
from wildburrow.core.sessions import Policy, Session
from wildburrow.core.types import Identity, TokenCredential
from wildburrow.core.users import Users
from wildburrow.store.database import Database, Storage
from wildburrow.store.record import Recorder
from wildburrow.store.users import UserStore

CAROL = Identity("carol", "password", "carol")


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[ServerContext]:
    database = Database(Storage(str(tmp_path / "users.db")), Clock())
    record = Recorder(database)
    await record.open("0.6.0", "host", "example.com", {})
    users = Users(UserStore(database))
    users.run_id = record.run_id
    await users.open(["root"], [])
    admins = dataclasses.replace(POLICY_ADMINS, database=users.admins)
    yield ServerContext(
        "example.com", 5, tmp_path, Authenticator([Fixed((TokenCredential,), Identity("carol", "token", "signed:c"))]),
        policy=Policy(admins), users=users, record=record,
    )  # fmt: skip
    await record.close()


def session(ctx: ServerContext, identity: Identity) -> tuple[Session, list[str]]:
    ended: list[str] = []
    return ctx.open_session(identity, "websocket", PEER, ended.append, {}), ended


async def joined(ctx: ServerContext, admin: Session, **request: Any) -> dict[str, Any]:
    invited = await ctx.invite(admin, {"name": "carol"})
    return await ctx.join({"code": invited["code"], **request}, "websocket", PEER)


async def test_only_an_admin_manages_users(ctx: ServerContext) -> None:
    someone, _ = session(ctx, Identity("someone", "password", "someone"))
    assert await ctx.user_listing(someone) == {"error": "only an admin can list users"}
    assert await ctx.invite(someone, {"name": "x"}) == {"error": "only an admin can invite"}
    assert await ctx.set_admin(someone, {"name": "x", "admin": True}) == {
        "error": "only an admin can change who is one"
    }
    assert await ctx.remove_user(someone, {"name": "x"}) == {"error": "only an admin can remove users"}


async def test_an_invite_is_joined_with_a_password_and_a_key(ctx: ServerContext) -> None:
    admin, _ = session(ctx, ADMIN)
    key = new_key()
    request = {"password": "carol's own", "public_key": key.line + " carol@laptop", "alias": "c"}
    assert await joined(ctx, admin, **request) == {"name": "carol"}
    name, hashed = ctx.users.password("c") or ("", "")
    assert name == "carol"
    assert PasswordHasher().verify(hashed, "carol's own")
    [row] = [user for user in (await ctx.user_listing(admin))["users"] if user["name"] == "carol"]
    assert (row["alias"], row["keys"]) == ("c", ["carol@laptop"])
    labelled = await joined(ctx, admin, public_key=new_key().line, label="phone")
    assert labelled == {"name": "carol"}
    # Joined again without an alias, the one they had stays.
    assert ctx.users.password("c") is not None
    assert sorted(row["keys"] for row in (await ctx.user_listing(admin))["users"] if row["name"] == "carol") == [
        ["carol@laptop", "phone"]
    ]


@pytest.mark.parametrize(
    ("request_", "answer"),
    [
        ({"public_key": "ssh-ed25519 nope"}, {"error": "that public key can't be read"}),
        ({}, {"error": "joining sets a password, a key, or both"}),
        ({"password": "x", "code": "wbi_wrong"}, {"error": "that invite can't be used: it was used, ended or ran out"}),
    ],
)
async def test_a_join_that_cant_work_says_why(ctx: ServerContext, request_: dict[str, Any], answer: dict) -> None:
    admin, _ = session(ctx, ADMIN)
    invited = await ctx.invite(admin, {"name": "carol"})
    assert await ctx.join({"code": invited["code"], **request_}, "websocket", PEER) == answer


async def test_an_invite_says_how_long_it_lasts_and_whether_it_will(ctx: ServerContext) -> None:
    admin, _ = session(ctx, ADMIN)
    invited = await ctx.invite(admin, {"name": "carol", "expires": 60})
    assert (invited["expires"], invited["memory"]) == (1_800_000_060, False)
    assert await ctx.invite(admin, {"name": "carol", "expires": "soon"}) == {
        "error": "an invite's expiry is in seconds"
    }  # fmt: skip
    assert await ctx.invite(admin, {"name": "root"}) == {"error": "root comes from the settings: change them there"}


async def test_an_admin_made_in_the_database_is_one_until_unmade(ctx: ServerContext) -> None:
    admin, _ = session(ctx, ADMIN)
    await joined(ctx, admin, password="pw")
    carol, _ = session(ctx, CAROL)
    assert CAROL not in ctx.policy.admins
    assert await ctx.set_admin(admin, {"name": "carol", "admin": True}) == {
        "name": "carol", "admin": True, "changed": True, "still": False, "memory": False,
    }  # fmt: skip
    assert CAROL in ctx.policy.admins
    assert "users" in await ctx.user_listing(carol)
    assert (await ctx.set_admin(admin, {"name": "carol", "admin": False}))["still"] is False
    assert await ctx.set_admin(admin, {"name": "root", "admin": False}) == {
        "error": "root comes from the settings: change them there"
    }  # fmt: skip


async def test_unmaking_an_admin_the_settings_also_make_says_so(ctx: ServerContext) -> None:
    admin, _ = session(ctx, ADMIN)
    ctx.policy = Policy(dataclasses.replace(POLICY_ADMINS, methods=frozenset({"password"}), database=ctx.users.admins))
    await joined(ctx, admin, password="pw")
    await ctx.set_admin(admin, {"name": "carol", "admin": True})
    assert (await ctx.set_admin(admin, {"name": "carol", "admin": False}))["still"] is True
    await joined(ctx, admin, public_key=new_key().line)
    ctx.policy = Policy(dataclasses.replace(POLICY_ADMINS, methods=frozenset({"key"}), database=ctx.users.admins))
    assert (await ctx.set_admin(admin, {"name": "carol", "admin": False}))["still"] is True


async def test_removing_a_user_ends_their_sessions(ctx: ServerContext) -> None:
    admin, _ = session(ctx, ADMIN)
    await joined(ctx, admin, password="pw")
    carol, ended = session(ctx, CAROL)
    _, untouched = session(ctx, Identity("dave", "password", "dave"))
    assert await ctx.remove_user(admin, {"name": "carol"}, 9) == {"name": "carol", "ended": [carol.id]}
    assert ended == ["carol was removed by root"]
    assert (carol.ended_by, untouched) == (9, [])
    assert await ctx.remove_user(admin, {"name": "carol"}) == {"error": "no user carol"}


async def test_a_token_for_a_database_users_name_logs_no_one_in(
    ctx: ServerContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin, _ = session(ctx, ADMIN)
    await joined(ctx, admin, password="pw")
    reasons: list[str | None] = []
    monkeypatch.setattr(ctx.record, "auth", lambda transport, method, peer, identity, reason: reasons.append(reason))
    assert await ctx.authenticate("websocket", TokenCredential("t"), PEER) is None
    assert reasons == [NOT_A_USER]


async def test_each_change_says_who_made_it_from_where_and_by_which_command(
    ctx: ServerContext, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO")
    admin, _ = session(ctx, ADMIN)
    commands = [ctx.record.command(admin, kind, {}) for kind in ("invite", "set-admin", "remove-user")]
    assert commands == [1, 2, 3]
    invited = await ctx.invite(admin, {"name": "carol"}, 1)
    await ctx.join({"code": invited["code"], "password": "pw", "public_key": new_key().line}, "websocket", PEER)
    assert await ctx.user_listing(admin) == {"users": await ctx.users.listing(), "memory": False}
    await ctx.set_admin(admin, {"name": "carol", "admin": True}, 2)
    await ctx.remove_user(admin, {"name": "carol"}, 3)
    database = ctx.users._store._database
    assert database is not None
    by = {"user": "root", "identity": "SHA256:root", "method": "key", "session": admin.id, "transport": "websocket",
          "address": PEER.host, "run": 1}  # fmt: skip
    joining = {"by": "join", "transport": "websocket", "address": PEER.host, "run": 1, "user": "carol"}
    events = await database.read("SELECT context FROM users_events WHERE name = 'carol'")
    assert [json.loads(context) for (context,) in events] == [
        {**by, "command": 1}, joining, {**by, "command": 2}, {**by, "command": 3},
    ]  # fmt: skip
    assert await database.read("SELECT created_by_command_id FROM invites") == [(1,)]
    assert await database.read("SELECT label FROM user_keys") == [("key",)]
    said = [record.getMessage() for record in caplog.records if record.name == "wildburrow.core.context"]
    assert said == ["root invited carol", f"carol joined from {PEER.host}", "root removed carol"]
