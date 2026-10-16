import asyncio
import contextlib
import functools

import pytest
from websockets.asyncio.client import connect as ws_connect

from tests.conftest import DOMAIN, TIMEOUT, Backend, Credentials, Running, StartServer, free_port, get, ssh_args
from tests.e2e.test_websocket import TOKEN, client_config, start_client, stop
from tests.e2e.test_websocket import Lines as Output
from wildburrow.auth.token import digest
from wildburrow.client import ssh
from wildburrow.client.retry import Backoff
from wildburrow.client.websocket import Client

pytestmark = pytest.mark.e2e

ENV = {
    "WILDBURROW_TRANSPORTS": "ssh,websocket",
    "WILDBURROW_AUTH": "key,password,token",
    "WILDBURROW_AUTH_TOKEN_HASHES": f"ci:{digest(TOKEN)}",
}


def fast() -> Backoff:
    return Backoff(0.05, 0.2)


def ports(running: Running) -> dict[str, str]:
    return {"WILDBURROW_HTTP_PORT": str(running.http_port), "WILDBURROW_SSH_PORT": str(running.ssh_port)}


async def restart(running: Running, start_server: StartServer) -> Running:
    same_ports = ports(running)
    await running.server.__aexit__(None, None, None)
    return await start_server(**ENV, **same_ports)


@contextlib.asynccontextmanager
async def ssh_client(running: Running, credentials: Credentials, method: str, port: int, wrong: bool = False):
    args, env = ssh_args(running.ssh_port, method, credentials, wrong=wrong)
    out = Output()
    command = [*args, "-R", f"app:80:127.0.0.1:{port}", "--", "tester@127.0.0.1"]
    task = asyncio.create_task(ssh.tunnel(command, out, env=env, backoff=fast()))
    try:
        yield task, out
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.mark.parametrize("method", ["key", "password"])
async def test_ssh_client_reconnects_after_a_restart(
    start_server: StartServer, credentials: Credentials, backend: Backend, method: str
) -> None:
    running = await start_server(**ENV)
    async with ssh_client(running, credentials, method, backend.port) as (_, out):
        await out.wait_for("ready:")
        out.lines.clear()
        running = await restart(running, start_server)
        await out.wait_for("connection lost; retrying in 0.05s")
        await out.wait_for("ready:")
        assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 200
    await asyncio.sleep(0.3)
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 404


async def test_ssh_client_does_not_retry_refused_logins(start_server: StartServer, credentials: Credentials) -> None:
    running = await start_server(**ENV)
    async with ssh_client(running, credentials, "key", 9, wrong=True) as (task, out):
        assert await asyncio.wait_for(task, TIMEOUT) == ssh.CONNECTION_FAILED
    assert not any("retrying" in line for line in out.lines)


@pytest.mark.parametrize("method", ["key", "password", "token"])
async def test_websocket_client_reconnects_after_a_restart(
    start_server: StartServer, credentials: Credentials, backend: Backend, method: str
) -> None:
    running = await start_server(**ENV)
    connector = functools.partial(ws_connect, host="127.0.0.1", port=running.http_port)
    config = client_config(credentials, method)
    task, out = start_client(running, config, backend.port, ["app"], connector=connector, backoff=fast())
    await out.wait_for("ready:")
    out.lines.clear()
    running = await restart(running, start_server)
    assert (await out.wait_for("connection lost: ")).endswith("; retrying in 0.05s")
    await out.wait_for("ready:")
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 200
    await stop(task)


async def test_websocket_client_waits_for_the_server(
    start_server: StartServer, credentials: Credentials, backend: Backend
) -> None:
    port = free_port()
    connector = functools.partial(ws_connect, host="127.0.0.1", port=port)
    out = Output()
    client = Client(
        client_config(credentials, "token"),
        backend.port,
        ["app"],
        "127.0.0.1",
        out=out,
        connector=connector,
        backoff=fast(),
    )
    task = asyncio.create_task(client.run())
    await out.wait_for("could not connect to ")
    running = await start_server(**ENV, WILDBURROW_HTTP_PORT=str(port))
    await out.wait_for("ready:")
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 200
    await stop(task)
