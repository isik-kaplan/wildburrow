import asyncio
import contextlib
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import TIMEOUT, Backend, Connect, Credentials, StartServer
from tests.e2e.test_locks import Browser, at
from tests.e2e.test_websocket import client_config, local, signed, start_client, stop
from wildburrow import cli, config, tokens
from wildburrow.client import websocket
from wildburrow.client.config import config_path, write_config
from wildburrow.client.locking import LockRequest

pytestmark = pytest.mark.e2e


def env(credentials: Credentials, path: Path, record: str = "everything") -> dict[str, str]:
    return {
        "WILDBURROW_TRANSPORTS": "ssh,websocket",
        "WILDBURROW_AUTH": "key,token",
        "WILDBURROW_AUTH_TOKEN_SIGNERS": credentials.public_key,
        "WILDBURROW_DATABASE": str(path),
        "WILDBURROW_DATABASE_RECORD": record,
    }


def read(path: Path, sql: str) -> list[tuple[Any, ...]]:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        return connection.execute(sql).fetchall()


async def test_a_run_is_recorded_in_full_and_a_denied_token_stays_denied(
    start_server: StartServer,
    credentials: Credentials,
    backend: Backend,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    # As `serve` logs.
    caplog.set_level(logging.INFO, "wildburrow")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    path = tmp_path / "data" / "wildburrow.db"
    running = await start_server(**env(credentials, path))
    token = signed(credentials, ("foo",))
    token_id = tokens.decode(token)[0].id
    lock = LockRequest({"alice": "wonderland"})
    task, out = start_client(
        running, client_config(credentials, "token", token=token), backend.port, ["foo"], lock=lock
    )
    await out.wait_for("locked:")
    logging.getLogger("elsewhere").warning("not the server's")
    browser = Browser(running.http_port)
    assert (await browser.visit(at("foo", "/page?q=1"))).status == 401
    form = {"username": "alice", "password": "wonderland", "to": "/page?q=1"}
    assert (await browser.visit(at("foo", "/_wildburrow/login"), "POST", form)).body == b"GET /page?q=1 HTTP/1.1"
    alice_config = client_config(credentials, "token", token=token)
    assert (await websocket.link(alice_config, {"url": at("foo")}, connector=local(running)))["label"] == "link-1"
    write_config(config_path(), client_config(credentials, "key"))
    monkeypatch.setattr(websocket, "connect", local(running))
    assert await asyncio.to_thread(cli.main, ["tokens", "deny", token_id]) == 0
    assert capsys.readouterr().out == f"denied {token_id}\nended 1 of their sessions\n"
    assert await out.wait_for("closed:") == "closed: its token was denied by laptop"
    await asyncio.wait_for(task, TIMEOUT)
    await running.server.__aexit__(None, None, None)

    assert read(path, "SELECT id, stopped_at IS NOT NULL FROM runs") == [(1, 1)]
    [(settings,)] = read(path, "SELECT settings FROM runs")
    settings = json.loads(settings)
    assert (settings["transports"], settings["auth"]) == (["ssh", "websocket"], ["key", "token"])
    assert sorted(read(path, "SELECT method, name FROM identities")) == [("key", "laptop"), ("token", "alice")]
    assert read(path, "SELECT id, name, revoked_at IS NOT NULL FROM tokens") == [(token_id, "alice", 1)]
    alices = (
        "SELECT sessions.id, transport, client_version, client_platform, end_reason, ended_by_command_id "
        "FROM sessions JOIN identities ON identity_id = identities.id WHERE name = 'alice' AND end_reason IS NOT NULL"
    )
    [(alice, transport, client_version, client_platform, reason, ended_by)] = read(path, alices)
    assert (transport, reason) == ("websocket", "its token was denied by laptop")
    assert (client_version, client_platform) == (websocket.CLIENT["version"], websocket.CLIENT["platform"])
    [(denial, request, answer)] = read(path, "SELECT id, request, answer FROM commands WHERE kind = 'deny'")
    assert ended_by == denial
    assert json.loads(request) == {"type": "deny", "tokens": [token_id]}
    assert json.loads(answer) == {"tokens": [token_id], "ended": [alice]}
    assert read(path, "SELECT closed_at IS NOT NULL, lock_id IS NOT NULL FROM tunnels") == [(1, 1)]
    assert read(path, "SELECT name FROM tunnel_names") == [("foo",)]
    [(link,)] = read(path, "SELECT id FROM commands WHERE kind = 'link'")
    assert read(path, "SELECT kind, label, logins, created_by_command_id FROM credentials ORDER BY label") == [
        ("password", "alice", 1, None), ("link", "link-1", 0, link)
    ]  # fmt: skip
    assert read(path, "SELECT via, label, ok FROM login_attempts") == [("form", "alice", 1)]
    requests = read(path, "SELECT method, path, query, status, credential_id IS NOT NULL FROM requests ORDER BY id")
    assert ("GET", "/page", "q=1", 401, 0) in requests
    assert ("GET", "/page", "q=1", 200, 1) in requests
    assert read(path, "SELECT count(*) > 0 FROM traffic") == [(1,)]
    assert read(path, "SELECT count(*) > 0 FROM logs") == [(1,)]
    assert read(path, "SELECT count(*) FROM logs WHERE logger NOT LIKE 'wildburrow%'") == [(0,)]

    running = await start_server(**env(credentials, path))
    task, out = start_client(running, client_config(credentials, "token", token=token), backend.port, ["foo"])
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert out.lines[-1] == "error: authentication failed"
    await running.server.__aexit__(None, None, None)
    assert read(path, "SELECT ok, reason FROM auth_attempts WHERE run_id = 2") == [(0, "denied")]


async def test_a_kicked_session_is_recorded_as_ended_by_the_kick(
    start_server: StartServer, credentials: Credentials, backend: Backend, tmp_path: Path
) -> None:
    path = tmp_path / "wildburrow.db"
    running = await start_server(**env(credentials, path))
    alice = client_config(credentials, "token", token=signed(credentials, ("foo",)))
    task, out = start_client(running, alice, backend.port, ["foo"])
    await out.wait_for("ready:")
    laptop = client_config(credentials, "key")
    answer = await websocket.kick(laptop, lambda listed, reach: [{"who": "alice"}], connector=local(running))
    assert len(answer["sessions"]) == 1
    await asyncio.wait_for(task, TIMEOUT)
    await running.server.__aexit__(None, None, None)
    [(kick,)] = read(path, "SELECT id FROM commands WHERE kind = 'kick'")
    assert read(path, "SELECT end_reason, ended_by_command_id FROM sessions WHERE end_reason IS NOT NULL") == [
        ("ended by laptop", kick)
    ]


async def test_minimal_keeps_nothing_once_its_over(
    start_server: StartServer, credentials: Credentials, backend: Backend, tmp_path: Path
) -> None:
    path = tmp_path / "wildburrow.db"
    running = await start_server(**env(credentials, path, "minimal"))
    task, out = start_client(running, client_config(credentials, "key"), backend.port, ["foo"])
    await out.wait_for("ready:")
    await stop(task)
    await running.server.__aexit__(None, None, None)
    for table in ("sessions", "tunnels", "auth_attempts", "connections", "logs"):
        assert read(path, f"SELECT count(*) FROM {table}") == [(0,)], table  # noqa: S608
    assert read(path, "SELECT name FROM identities") == [("laptop",)]


async def test_only_an_admin_denies_tokens(
    start_server: StartServer, credentials: Credentials, backend: Backend, tmp_path: Path
) -> None:
    running = await start_server(**env(credentials, tmp_path / "wildburrow.db"))
    someone = client_config(credentials, "token", token=signed(credentials, None, who="someone"))
    assert await websocket.deny(someone, ["t"], connector=local(running)) == {
        "type": "denied", "error": "only an admin can deny tokens"
    }  # fmt: skip
    await running.server.__aexit__(None, None, None)


async def test_a_database_the_server_cant_use_stops_it(
    start_server: StartServer, credentials: Credentials, tmp_path: Path
) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("not a database, just long enough to look like a header to sqlite\n" * 4)
    with pytest.raises(config.ConfigError, match=f"^WILDBURROW_DATABASE: {path} can't be opened as a database: "):
        await start_server(**env(credentials, path))


async def test_an_ssh_login_is_recorded_as_one(
    start_server: StartServer, credentials: Credentials, backend: Backend, connect: Connect, tmp_path: Path
) -> None:
    path = tmp_path / "wildburrow.db"
    running = await start_server(**env(credentials, path, "activity"))
    ssh = await connect(running.ssh_port, "key", "-R", f"app:80:127.0.0.1:{backend.port}")
    await ssh.line("ready:")
    await running.server.__aexit__(None, None, None)
    assert read(path, "SELECT transport, method, ok FROM auth_attempts") == [("ssh", "key", 1)]
    assert read(path, "SELECT transport, client_version FROM sessions") == [("ssh", None)]
