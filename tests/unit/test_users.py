import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import asyncssh
import pytest

from tests.unit.test_store import NOW, Clock
from wildburrow.config import ConfigError
from wildburrow.core.types import Identity
from wildburrow.core.users import INVITE_PREFIX, Key, UserError, Users, digest, public_data
from wildburrow.store.database import Database, Storage
from wildburrow.store.users import UserStore, in_memory

HASH = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA"
OTHER_HASH = "$argon2id$v=19$m=65536,t=3,p=4$b3RoZXJzYWx0$b3RoZXI"
BY = {"user": "root", "identity": "SHA256:root", "method": "key"}


def new_key(label: str = "laptop") -> Key:
    key = asyncssh.generate_private_key("ssh-ed25519")
    return Key(key.export_public_key().decode().strip(), key.get_fingerprint(), label)


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[Database]:
    found = Database(Storage(str(tmp_path / "users.db")), Clock())
    await found.open()
    yield found
    await found.close()


async def opened(database: Database, *names: str, keys: tuple[str, ...] = ()) -> Users:
    users = Users(UserStore(database))
    users.run_id = 1
    await users.open(names, keys)
    return users


async def rows(database: Database, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    return await database.read(sql, *params)


async def invited(users: Users, name: str = "carol", **joined: Any) -> str:
    code, _ = await users.invite(name, BY)
    await users.join(code, joined.get("password", HASH), joined.get("key"), joined.get("alias"), {"by": "join"})
    return code


async def test_the_settings_users_are_kept_in_line_with_the_settings(database: Database) -> None:
    await opened(database, "alice", "bob")
    assert await rows(database, "SELECT name, source, gone_at FROM users ORDER BY name") == [
        ("alice", "settings", None), ("bob", "settings", None),
    ]  # fmt: skip
    await opened(database, "alice")
    assert await rows(database, "SELECT name, gone_at FROM users ORDER BY name") == [("alice", None), ("bob", NOW)]
    users = await opened(database, "alice", "bob")
    assert await rows(database, "SELECT name, gone_at FROM users ORDER BY name") == [("alice", None), ("bob", None)]
    assert users.id_of(Identity("bob", "password", "bob")) == 2
    assert users.id_of(Identity("nobody", "password", "nobody")) is None
    # Nothing changed, nothing written.
    before = await rows(database, "SELECT count(*) FROM users_events")
    await opened(database, "alice", "bob")
    assert await rows(database, "SELECT count(*) FROM users_events") == before
    [(context,)] = await rows(database, "SELECT DISTINCT context FROM users_events")
    assert json.loads(context) == {"by": "settings", "run": 1}


async def test_a_token_holder_named_in_the_settings_becomes_theirs(database: Database) -> None:
    users = await opened(database)
    assert await users.admit(Identity("dan", "token", "signed:dan"))
    settled = await opened(database, "dan")
    assert await rows(database, "SELECT source FROM users WHERE name = 'dan'") == [("settings",)]
    assert await settled.admit(Identity("dan", "password", "dan"))
    # Taken out of the settings, they can't log in from the start.
    assert not await (await opened(database)).admit(Identity("dan", "password", "dan"))


@pytest.mark.parametrize("name", ["carol", "c"])
async def test_the_settings_cant_name_a_database_users_name_or_alias(database: Database, name: str) -> None:
    users = await opened(database)
    await invited(users, alias="c")
    with pytest.raises(ConfigError, match=f"^{name}: in the settings and a database user's too; .*WILDBURROW_AUTH_"):
        await opened(database, name, "zed")
    await users.remove("carol", BY)
    with pytest.raises(ConfigError):
        await opened(database, name)


async def test_every_name_the_settings_take_from_the_database_is_said(database: Database) -> None:
    users = await opened(database)
    await invited(users, alias="c")
    with pytest.raises(ConfigError, match=r"^c, carol: in the settings"):
        await opened(database, "carol", "c")


async def test_who_may_log_in_as_their_user(database: Database) -> None:
    users = await opened(database, "alice", "gone")
    await opened(database, "alice")
    users = await opened(database, "alice")
    await invited(users, alias="c")
    assert await users.admit(Identity("alice", "password", "alice"))
    assert await users.admit(Identity("carol", "password", "carol"))
    assert await users.admit(Identity("stranger", "key", "SHA256:x"))
    assert not await users.admit(Identity("gone", "password", "gone"))
    assert not await users.admit(Identity("c", "password", "c"))
    # A token signed for a database user's name isn't theirs, nor for their alias.
    assert not await users.admit(Identity("carol", "token", "signed:carol"))
    assert not await users.admit(Identity("c", "token", "signed:c"))
    assert await users.admit(Identity("alice", "token", "signed:alice"))
    assert await users.admit(Identity("dan", "token", "signed:dan"))
    assert users.id_of(Identity("dan", "token", "signed:dan")) == 4
    assert [user["source"] for user in await users.listing() if user["name"] == "dan"] == ["token"]
    assert await users.admit(Identity("gone", "token", "signed:gone"))
    assert [user["gone"] for user in await users.listing() if user["name"] == "gone"] == [False]
    assert await rows(database, "SELECT name, source, gone_at FROM users WHERE source = 'token' ORDER BY name") == [
        ("dan", "token", None), ("gone", "token", None),
    ]  # fmt: skip
    await users.remove("carol", BY)
    assert not await users.admit(Identity("carol", "password", "carol"))
    contexts = await rows(database, "SELECT context FROM users_events WHERE name = 'dan'")
    assert [json.loads(context) for (context,) in contexts] == [{"by": "token", "identity": "signed:dan", "run": 1}]


@pytest.mark.parametrize(
    ("name", "seconds", "message"),
    [
        ("a b", 60, "'a b' can't be a name: 1-64 characters, with no spaces or colons"),
        ("x" * 65, 60, f"'{'x' * 65}' can't be a name: 1-64 characters, with no spaces or colons"),
        ("carol", 0, "an invite has to last at least a second"),
        ("alice", 60, "alice comes from the settings: change them there"),
        ("c", 60, "c is another user's alias"),
    ],
)
async def test_what_cant_be_invited(database: Database, name: str, seconds: int, message: str) -> None:
    users = await opened(database, "alice")
    await invited(users, "zed", alias="c")
    with pytest.raises(UserError) as error:
        await users.invite(name, BY, seconds)
    assert str(error.value) == message


async def test_an_invite_is_one_time_and_a_newer_one_ends_it(database: Database) -> None:
    users = await opened(database)
    first, expires = await users.invite("carol", BY, 1, command=None)
    assert first.startswith(INVITE_PREFIX)
    # 24 random bytes, as 32 characters.
    assert len(first) == len(INVITE_PREFIX) + 32
    assert expires == NOW + 1
    second, _ = await users.invite("carol", BY)
    with pytest.raises(UserError, match=r"^that invite can.t be used: it was used, ended or ran out$"):
        await users.join(first, HASH, None, None, {})
    assert await users.join(second, HASH, None, None, {}) == "carol"
    with pytest.raises(UserError):
        await users.join(second, HASH, None, None, {})
    assert await rows(database, "SELECT digest = ?, used_at, ended_at FROM invites ORDER BY id", digest(first)) == [
        (1, None, NOW), (0, NOW, None),
    ]  # fmt: skip


async def test_an_invite_runs_out(database: Database) -> None:
    users = await opened(database)
    code, _ = await users.invite("carol", BY, 60)
    database._clock.now += 60  # type: ignore[attr-defined]
    with pytest.raises(UserError):
        await users.join(code, HASH, None, None, {})


async def test_joining_sets_a_password_a_key_and_an_alias(database: Database) -> None:
    users = await opened(database)
    key = new_key()
    await invited(users, key=key, alias="c")
    assert users.password("carol") == ("carol", HASH)
    assert users.password("c") == ("carol", HASH)
    assert users.password("nobody") is None
    assert users.key(public_data(key.line)) == ("carol", key.fingerprint, "laptop")
    assert users.key(b"unknown") is None
    assert (await opened(database)).key(public_data(key.line)) == ("carol", key.fingerprint, "laptop")
    assert users.identities("carol") == [
        Identity("carol", "password", "carol"), Identity("carol@laptop", "key", key.fingerprint, owner="carol"),
    ]  # fmt: skip
    # A new invite, to change only the password, keeps the key and the alias.
    code, _ = await users.invite("carol", BY)
    await users.join(code, OTHER_HASH, key, None, {})
    assert users.password("c") == ("carol", OTHER_HASH)
    reloaded = await opened(database)
    assert (reloaded.password("c"), reloaded.admins) == (("carol", OTHER_HASH), set())
    assert users.key(public_data(key.line)) is not None
    assert await rows(database, "SELECT count(*) FROM user_keys") == [(1,)]
    # And one with only a key keeps the password.
    code, _ = await users.invite("carol", BY)
    await users.join(code, None, new_key("phone"), "carol2", {})
    assert users.password("carol2") == ("carol", OTHER_HASH)
    assert users.password("c") is None
    assert await rows(database, "SELECT alias, password_hash = ? FROM users", OTHER_HASH) == [("carol2", 1)]


async def test_joining_with_no_login_or_a_taken_one_is_refused(database: Database) -> None:
    settings_key, other = new_key(), new_key()
    users = await opened(database, "alice", keys=(settings_key.fingerprint,))
    await invited(users, "zed", key=other, alias="z")
    code, _ = await users.invite("carol", BY)
    for password, key, alias, message in [
        (None, None, None, "joining sets a password, a key, or both"),
        (HASH, None, "a b", "'a b' can't be a name: 1-64 characters, with no spaces or colons"),
        (HASH, None, "alice", "alice is taken"),
        (HASH, None, "z", "z is taken"),
        (HASH, None, "carol", "carol is taken"),
        (None, settings_key, None, "that key already logs someone else in"),
        (None, other, None, "that key already logs someone else in"),
    ]:
        with pytest.raises(UserError) as error:
            await users.join(code, password, key, alias, {})
        assert str(error.value) == message
    assert await users.join(code, HASH, None, None, {}) == "carol"


async def test_admins_are_made_and_unmade_only_among_database_users(database: Database) -> None:
    users = await opened(database, "alice")
    await invited(users)
    assert await users.set_admin("carol", True, BY)
    assert not await users.set_admin("carol", True, BY)
    assert users.admins == {"carol"}
    assert (await opened(database, "alice")).admins == {"carol"}
    assert await users.set_admin("carol", False, BY)
    assert users.admins == set()
    for name, message in [("alice", "alice comes from the settings: change them there"), ("nobody", "no user nobody")]:
        with pytest.raises(UserError) as error:
            await users.set_admin(name, True, BY)
        assert str(error.value) == message


async def test_a_removed_user_logs_in_no_more_until_invited_again(database: Database) -> None:
    users = await opened(database)
    key = new_key()
    await invited(users, key=key, alias="c")
    await users.set_admin("carol", True, BY)
    await users.invite("carol", BY)
    await users.remove("carol", BY)
    assert (users.password("carol"), users.key(public_data(key.line)), users.admins) == (None, None, set())
    assert await rows(database, "SELECT gone_at, admin, password_hash FROM users") == [(NOW, 0, None)]
    assert await rows(database, "SELECT removed_at FROM user_keys") == [(NOW,)]
    assert await rows(database, "SELECT count(*) FROM invites WHERE used_at IS NULL AND ended_at IS NULL") == [(0,)]
    with pytest.raises(UserError, match=r"^no user carol$"):
        await users.remove("carol", BY)
    reloaded = await opened(database)
    assert reloaded.password("carol") is None
    # Invited again, they set up a new login; the alias stays theirs.
    code, _ = await reloaded.invite("carol", BY)
    assert reloaded.password("carol") is None
    await reloaded.join(code, HASH, None, None, {})
    assert reloaded.password("c") == ("carol", HASH)


async def test_users_are_listed_without_their_secrets(database: Database) -> None:
    users = await opened(database, "alice")
    key = new_key("phone")
    await invited(users, key=key, alias="c")
    await users.invite("dave", BY, 60)
    assert await users.listing() == [
        {"name": "alice", "alias": None, "source": "settings", "admin": False, "password": False, "keys": [],
         "invited_until": None, "gone": False},
        {"name": "carol", "alias": "c", "source": "database", "admin": False, "password": True, "keys": ["phone"],
         "invited_until": None, "gone": False},
        {"name": "dave", "alias": None, "source": "database", "admin": False, "password": False, "keys": [],
         "invited_until": NOW + 60, "gone": False},
    ]  # fmt: skip


async def test_every_change_is_an_event_with_who_made_it(database: Database) -> None:
    users = await opened(database)
    key = new_key()
    await invited(users, key=key)
    await users.remove("carol", BY)
    events = await rows(database, "SELECT label, context FROM users_events")
    assert [label for label, _ in events] == ["insert", "update", "update"]
    assert [json.loads(context) for _, context in events] == [
        {**BY, "run": 1}, {"by": "join", "run": 1, "user": "carol"}, {**BY, "run": 1},
    ]  # fmt: skip
    assert await rows(database, "SELECT label, key_label FROM user_keys_events") == [
        ("insert", "laptop"), ("update", "laptop"),
    ]  # fmt: skip
    assert await rows(database, "SELECT label FROM invites_events") == [("insert",), ("update",)]
    columns = {column for (_, column, *_) in await rows(database, "PRAGMA table_info(invites_events)")}
    assert "digest" not in columns


async def test_without_a_database_nothing_is_kept() -> None:
    store = UserStore(None)
    assert (store.memory, in_memory(None), store.next_id("users"), store.now()) == (True, True, 0, 0)
    assert (await store.load(), await store.invite_for("x"), await store.pending()) == ([], None, {})
    await store.write({}, ("SELECT 1", ()))
    users = Users(store)
    await users.open(["alice"], [])
    assert users.memory
    assert await users.admit(Identity("alice", "password", "alice"))


async def test_a_database_in_memory_says_so() -> None:
    assert in_memory(Database(Storage()))
    assert not in_memory(Database(Storage("/x.db")))


async def test_a_key_only_login_and_who_its_for(database: Database) -> None:
    users = Users(UserStore(database))
    # Before the settings are read, as much as after.
    key = new_key()
    code, _ = await users.invite("carol", BY)
    await users.join(code, None, key, None, {})
    assert [(identity, identity.user) for identity in users.identities("carol")] == [
        (Identity("carol@laptop", "key", key.fingerprint), "carol")
    ]


async def test_a_removed_users_key_can_be_joined_with_again(database: Database) -> None:
    users = await opened(database)
    key = new_key()
    await invited(users, key=key, alias="c")
    await users.set_admin("carol", True, BY)
    await users.remove("carol", BY)
    [carol] = [user for user in await users.listing() if user["name"] == "carol"]
    assert (carol["admin"], carol["gone"], carol["keys"]) == (False, True, [])
    await invited(users, "dave", key=key)
    assert users.key(public_data(key.line)) == ("dave", key.fingerprint, "laptop")
    assert await rows(database, "SELECT user_id, removed_at FROM user_keys ORDER BY id") == [(1, NOW), (2, None)]


async def test_a_user_gone_by_a_hand_edit_logs_in_no_more(database: Database) -> None:
    users = await opened(database)
    await invited(users)
    await database.write_now({}, ("UPDATE users SET gone_at = 1 WHERE name = 'carol'", ()))
    assert (await opened(database)).password("carol") is None
