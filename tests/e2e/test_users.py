import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import Credentials, StartServer
from tests.e2e.test_websocket import client_config, local
from wildburrow import protocol
from wildburrow.client import websocket
from wildburrow.client.websocket import ClientError, websocket_base

pytestmark = pytest.mark.e2e


def env(credentials: Credentials, path: Path | None) -> dict[str, str]:
    return {
        "WILDBURROW_TRANSPORTS": "websocket",
        "WILDBURROW_AUTH": "key,password",
        "WILDBURROW_ADMINS": "key:laptop",
        "WILDBURROW_DATABASE": "" if path is None else str(path),
    }


def read(path: Path, sql: str) -> list[tuple[Any, ...]]:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        return connection.execute(sql).fetchall()


async def test_an_invited_user_joins_logs_in_and_can_be_made_an_admin_and_removed(
    start_server: StartServer, credentials: Credentials, tmp_path: Path
) -> None:
    path = tmp_path / "wildburrow.db"
    running = await start_server(**env(credentials, path))
    laptop, connector = client_config(credentials, "key"), local(running)
    invited = await websocket.invite(laptop, "carol", None, connector=connector)
    assert (invited["name"], invited["memory"]) == ("carol", False)
    joining = client_config(credentials, "password")
    request = {"code": invited["code"], "password": "carol's own", "alias": "c"}
    assert await websocket.join(joining, request, connector=connector) == "carol"
    # Spent: said so in a joined message, the one answer to a join.
    async with connector(f"{websocket_base(joining)}{protocol.CONNECT_PATH}") as control:
        await control.send(protocol.encode(protocol.JOIN, **request))
        assert protocol.decode(await control.recv()) == {
            "type": "joined", "error": "that invite can't be used: it was used, ended or ran out"
        }  # fmt: skip

    carol = client_config(credentials, "password", user="c")
    listed = await websocket.users(carol, lambda prompt: "carol's own", connector=connector)
    assert listed == {"type": "users", "error": "only an admin can list users"}
    assert (await websocket.set_admin(laptop, "carol", True, connector=connector))["changed"] is True
    found = await websocket.users(carol, lambda prompt: "carol's own", connector=connector)
    [row] = [user for user in found["users"] if user["name"] == "carol"]
    assert (row["alias"], row["source"], row["admin"], row["password"]) == ("c", "database", True, True)
    with pytest.raises(ClientError):
        await websocket.users(carol, lambda prompt: "wrong", connector=connector)

    assert (await websocket.remove_user(laptop, "carol", connector=connector))["name"] == "carol"
    with pytest.raises(ClientError):
        await websocket.users(carol, lambda prompt: "carol's own", connector=connector)
    await running.server.__aexit__(None, None, None)

    events = read(path, "SELECT label, name, admin, password_set, context FROM users_events WHERE name = 'carol'")
    assert [(label, admin, password) for label, _, admin, password, _ in events] == [
        ("insert", 0, 0), ("update", 0, 1), ("update", 1, 1), ("update", 0, 0),
    ]  # fmt: skip
    contexts = [json.loads(context) for *_, context in events]
    assert {context.get("user") for context in contexts} == {"laptop", "carol"}
    assert all((context["run"], context["transport"]) == (1, "websocket") for context in contexts)
    # Each change an admin made points at the command that made it.
    commands = dict(read(path, "SELECT kind, id FROM commands WHERE kind IN ('invite', 'set-admin', 'remove-user')"))
    assert [context.get("command") for context in contexts] == [
        commands["invite"], None, commands["set-admin"], commands["remove-user"],
    ]  # fmt: skip
    assert read(path, "SELECT created_by_command_id FROM invites") == [(commands["invite"],)]
    assert read(path, "SELECT count(*) FROM users_events WHERE context IS NULL") == [(0,)]
    assert "password_hash" not in {column for (_, column, *_) in read(path, "PRAGMA table_info(users_events)")}
    [(answer,)] = read(path, "SELECT answer FROM commands WHERE kind = 'invite'")
    assert "code" not in json.loads(answer)


async def test_a_settings_name_cant_be_invited_or_taken_by_the_database(
    start_server: StartServer, credentials: Credentials, tmp_path: Path
) -> None:
    path = tmp_path / "wildburrow.db"
    running = await start_server(**env(credentials, path))
    laptop, connector = client_config(credentials, "key"), local(running)
    refused = await websocket.invite(laptop, "tester", None, connector=connector)
    assert refused["error"] == "tester comes from the settings: change them there"
    await websocket.invite(laptop, "dave", None, connector=connector)
    await running.server.__aexit__(None, None, None)
    with pytest.raises(Exception, match="dave: in the settings and a database user's too"):
        await start_server(**env(credentials, path), WILDBURROW_AUTH_PASSWORD_USERS=f"dave:{credentials.password_hash}")


async def test_without_a_database_file_invites_say_they_wont_last(
    start_server: StartServer, credentials: Credentials, caplog: pytest.LogCaptureFixture
) -> None:
    running = await start_server(**env(credentials, None))
    assert any("users invited while the server runs" in message for message in caplog.messages)
    invited = await websocket.invite(client_config(credentials, "key"), "erin", None, connector=local(running))
    assert invited["memory"] is True


async def test_an_invited_user_logs_in_with_the_key_they_joined_with(
    start_server: StartServer, credentials: Credentials, tmp_path: Path
) -> None:
    running = await start_server(**env(credentials, tmp_path / "wildburrow.db"))
    laptop, connector = client_config(credentials, "key"), local(running)
    stranger = client_config(credentials, "key", identity=str(credentials.other_key))
    with pytest.raises(ClientError):
        await websocket.users(stranger, connector=connector)
    invited = await websocket.invite(laptop, "carol", None, connector=connector)
    public = credentials.other_key.with_suffix(".pub").read_text().strip()
    request = {"code": invited["code"], "public_key": public, "label": "phone"}
    assert await websocket.join(stranger, request, connector=connector) == "carol"
    # Not an admin, but in: told so, rather than turned away at the door.
    assert await websocket.users(stranger, connector=connector) == {
        "type": "users", "error": "only an admin can list users"
    }  # fmt: skip
    listed = await websocket.users(laptop, connector=connector)
    [carol] = [user for user in listed["users"] if user["name"] == "carol"]
    assert (carol["keys"], carol["password"]) == (["phone"], False)
