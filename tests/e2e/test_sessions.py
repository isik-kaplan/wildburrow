import asyncio
import time

import pytest
from websockets.exceptions import ConnectionClosed

from tests.conftest import DOMAIN, TIMEOUT, Backend, Connect, Credentials, Running, StartServer
from tests.e2e.test_websocket import client_config, local, raw_control, signed, start_client, stop
from wildburrow import protocol, tokens
from wildburrow.client import websocket
from wildburrow.core.sessions import GRACE_SECONDS

pytestmark = pytest.mark.e2e


@pytest.fixture
def env(credentials: Credentials) -> dict[str, str]:
    return {
        "WILDBURROW_TRANSPORTS": "ssh,websocket",
        "WILDBURROW_AUTH": "key,token",
        "WILDBURROW_AUTH_TOKEN_SIGNERS": credentials.public_key,
    }


async def test_a_tunnel_ends_when_its_token_expires(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    running = await start_server(**env)
    token = signed(credentials, None, int(time.time()) - GRACE_SECONDS + 2)
    task, out = start_client(running, client_config(credentials, "token", token=token), backend.port, ["alice"])
    assert await out.wait_for("ready:") == f"ready: http://alice.{DOMAIN}"
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert await out.wait_for("closed:") == "closed: the token expired"
    await gone(running)


async def gone(running: Running) -> None:
    """Waits for the server to let go of every name and session, which it does after telling the client."""
    async with asyncio.timeout(TIMEOUT):
        while running.server.ctx.registry.names() or list(running.server.ctx.sessions):
            await asyncio.sleep(0.01)


async def test_admins_see_everyone_and_others_only_themselves(
    start_server: StartServer, credentials: Credentials, backend: Backend, connect: Connect, env: dict[str, str]
) -> None:
    running = await start_server(**env, WILDBURROW_SEE="admins", WILDBURROW_KICK="admins")
    alice = client_config(credentials, "token", token=signed(credentials, ("alice",)))
    task, out = start_client(running, alice, backend.port, ["alice"])
    await out.wait_for("ready:")
    ssh = await connect(running.ssh_port, "key", "-R", f"app:80:127.0.0.1:{backend.port}")
    await ssh.line("ready:")
    seen = await websocket.sessions(client_config(credentials, "key"), connector=local(running))
    assert sorted(
        (entry["who"], entry["via"], entry["transport"], entry["names"], entry["yours"]) for entry in seen
    ) == [
        ("alice", "token", "websocket", ["alice"], False),
        ("laptop", "key", "ssh", ["app"], True),
    ]
    assert {entry.get("from") for entry in seen} == {"127.0.0.1"}
    [own] = await websocket.sessions(alice, connector=local(running))
    assert (own["who"], own["names"], own["yours"], own["from"]) == ("alice", ["alice"], True, "127.0.0.1")
    await stop(task)


async def test_an_admin_ends_a_token_tunnel(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    running = await start_server(**env, WILDBURROW_SEE="admins", WILDBURROW_KICK="admins")
    token = signed(credentials, ("alice",))
    task, out = start_client(running, client_config(credentials, "token", token=token), backend.port, ["alice"])
    await out.wait_for("ready:")
    answer = await websocket.kick(client_config(credentials, "key"), {"who": "alice"}, connector=local(running))
    [ended] = answer["sessions"]
    grant, _, _ = tokens.decode(token)
    assert (ended["who"], ended["token"], ended["yours"], answer["refused"]) == ("alice", grant.id, False, [])
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert await out.wait_for("closed:") == "closed: ended by laptop"
    await gone(running)


async def test_the_same_token_ends_its_own_other_session(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    running = await start_server(**env)
    alice = client_config(credentials, "token", token=signed(credentials, ("alice", "*.alice")))
    work, out = start_client(running, alice, backend.port, ["*.alice"])
    await out.wait_for("ready:")
    laptop = client_config(credentials, "token", token=signed(credentials, ("alice",)))
    answer = await websocket.kick(laptop, {"name": "x.alice"}, connector=local(running))
    assert answer["sessions"] == []
    answer = await websocket.kick(laptop, {"name": "*.alice"}, connector=local(running))
    assert [entry["yours"] for entry in answer["sessions"]] == [True]
    assert await asyncio.wait_for(work, TIMEOUT) == 1
    assert await out.wait_for("closed:") == "closed: ended by alice"


async def test_an_ssh_tunnel_is_ended_over_websocket(
    start_server: StartServer, credentials: Credentials, backend: Backend, connect: Connect, env: dict[str, str]
) -> None:
    running = await start_server(**env)
    ssh = await connect(running.ssh_port, "key", "-R", f"app:80:127.0.0.1:{backend.port}")
    await ssh.line("ready:")
    answer = await websocket.kick(client_config(credentials, "key"), {"name": "app"}, connector=local(running))
    assert [(entry["transport"], entry["names"]) for entry in answer["sessions"]] == [("ssh", ["app"])]
    assert await ssh.line("closed:") == "closed: ended by laptop"
    assert await ssh.wait() != 0
    await gone(running)


async def test_others_are_out_of_reach(
    start_server: StartServer, credentials: Credentials, backend: Backend, connect: Connect, env: dict[str, str]
) -> None:
    running = await start_server(**env)
    ssh = await connect(running.ssh_port, "key", "-R", f"app:80:127.0.0.1:{backend.port}")
    await ssh.line("ready:")
    [session] = running.server.ctx.sessions
    alice = client_config(credentials, "token", token=signed(credentials, None))
    assert await websocket.sessions(alice, connector=local(running)) == []
    assert await websocket.kick(alice, {"session": session.id}, connector=local(running)) == {
        "type": "kicked",
        "sessions": [],
        "refused": [],
    }
    assert running.server.ctx.registry.names() != []


async def test_admins_can_be_kept_from_each_other(
    start_server: StartServer, credentials: Credentials, backend: Backend, connect: Connect, env: dict[str, str]
) -> None:
    running = await start_server(**env, WILDBURROW_ADMINS="all", WILDBURROW_SEE="all", WILDBURROW_KICK="admins")
    ssh = await connect(running.ssh_port, "key", "-R", f"app:80:127.0.0.1:{backend.port}")
    await ssh.line("ready:")
    alice = client_config(credentials, "token", token=signed(credentials, None))
    [seen] = await websocket.sessions(alice, connector=local(running))
    answer = await websocket.kick(alice, {"session": seen["id"]}, connector=local(running))
    assert (answer["sessions"], answer["refused"]) == ([], [seen["id"]])


async def test_sessions_need_a_login(start_server: StartServer, env: dict[str, str]) -> None:
    running = await start_server(**env)
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("sessions"))
        with pytest.raises(ConnectionClosed):
            await ws.recv()
        assert (ws.close_code, ws.close_reason) == (protocol.CLOSE_PROTOCOL_ERROR, "expected hello")
