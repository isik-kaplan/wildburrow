import asyncio
import functools
import json
import os
import ssl
import sys
from pathlib import Path

import pytest
from websockets.asyncio.client import connect

from tests import acme_env
from tests.conftest import DOMAIN, PASSWORD, TIMEOUT, Backend, Connect, Credentials, Running, StartServer, get, http
from wildburrow import protocol
from wildburrow.auth.token import digest, new_token
from wildburrow.client.config import ClientConfig
from wildburrow.client.websocket import Client

pytestmark = pytest.mark.e2e

TOKEN = new_token()
METHODS = ["key", "password", "token"]
SERVER_AUTH = ["key", "password", "token", "key,password,token"]


@pytest.fixture
def ws_env(credentials: Credentials) -> dict[str, str]:
    return {
        "WILDBURROW_TRANSPORTS": "ssh,websocket",
        "WILDBURROW_AUTH": "key,password,token",
        "WILDBURROW_AUTH_TOKEN_HASHES": f"ci:{digest(TOKEN)}",
    }


class Lines:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.changed = asyncio.Event()

    def __call__(self, line: str) -> None:
        self.lines.append(line)
        self.changed.set()

    async def wait_for(self, prefix: str) -> str:
        async with asyncio.timeout(TIMEOUT):
            while True:
                for line in self.lines:
                    if line.startswith(prefix):
                        return line
                self.changed.clear()
                await self.changed.wait()


def client_config(credentials: Credentials, method: str, **overrides: str) -> ClientConfig:
    values = {
        "server": DOMAIN,
        "user": "tester",
        "transport": "websocket",
        "auth": method,
        "identity": str(credentials.key),
        "token": TOKEN,
        "url": f"http://{DOMAIN}",
    }
    return ClientConfig(**(values | overrides))


def local(running: Running) -> functools.partial:
    return functools.partial(connect, host="127.0.0.1", port=running.http_port)


def start_client(
    running: Running, config: ClientConfig, port: int, names: list[str], password: str = PASSWORD, **kwargs
) -> tuple[asyncio.Task[int], Lines]:
    out = Lines()
    kwargs.setdefault("connector", local(running))
    client = Client(config, port, names, "127.0.0.1", ask=lambda prompt: password, out=out, **kwargs)
    return asyncio.create_task(client.run()), out


async def stop(task: asyncio.Task[int]) -> None:
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize("server_auth", SERVER_AUTH)
@pytest.mark.parametrize("method", METHODS)
async def test_auth_matrix(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env, server_auth: str, method: str
) -> None:
    running = await start_server(**{**ws_env, "WILDBURROW_AUTH": server_auth})
    task, out = start_client(running, client_config(credentials, method), backend.port, ["app"])
    if method in server_auth.split(","):
        assert await out.wait_for("ready:") == f"ready: http://app.{DOMAIN}"
        assert await get(running.http_port, f"app.{DOMAIN}", "/w") == (200, b"GET /w HTTP/1.1")
        await stop(task)
    else:
        assert await asyncio.wait_for(task, TIMEOUT) == 1
        assert await out.wait_for("error:") == "error: authentication failed"


@pytest.mark.parametrize("method", METHODS)
async def test_wrong_credentials(
    start_server: StartServer, credentials: Credentials, ws_env, method: str, tmp_path: Path
) -> None:
    running = await start_server(**ws_env)
    overrides = {"identity": str(credentials.other_key), "token": new_token()}
    task, out = start_client(running, client_config(credentials, method, **overrides), 9, ["app"], password="wrong")
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert await out.wait_for("error:") == "error: authentication failed"


@pytest.mark.parametrize("transport", ["ssh", "websocket"])
async def test_both_transports_share_names(
    start_server: StartServer, connect: Connect, credentials: Credentials, backend: Backend, ws_env, transport: str
) -> None:
    running = await start_server(**ws_env)
    if transport == "ssh":
        first = await connect(running.ssh_port, "key", "-R", f"*.foo:80:127.0.0.1:{backend.port}")
        await first.line("ready:")
        task, out = start_client(running, client_config(credentials, "token"), backend.port, ["*.foo"])
        assert (await out.wait_for("rejected:")).endswith("*.foo is already bound by laptop")
        assert await asyncio.wait_for(task, TIMEOUT) == 1
    else:
        task, out = start_client(running, client_config(credentials, "token"), backend.port, ["*.foo", "*.bar.foo"])
        await out.wait_for("ready: http://*.bar.foo")
        second = await connect(running.ssh_port, "key", "-R", f"*.foo:80:127.0.0.1:{backend.port}")
        assert await second.line("rejected:") == "rejected: *.foo is already bound by ci"
        assert await second.wait() == 1
        await stop(task)


async def test_the_same_key_moves_a_name_across_transports(
    start_server: StartServer, connect: Connect, credentials: Credentials, backend: Backend, ws_env
) -> None:
    running = await start_server(**ws_env)
    first = await connect(running.ssh_port, "key", "-R", "*.foo:80:127.0.0.1:9")
    await first.line("ready:")
    task, out = start_client(running, client_config(credentials, "key"), backend.port, ["*.foo"])
    await out.wait_for("ready:")
    assert (await get(running.http_port, f"a.foo.{DOMAIN}"))[0] == 200
    await stop(task)


async def test_routing_streams_and_disconnect(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env
) -> None:
    running = await start_server(**ws_env)
    task, out = start_client(running, client_config(credentials, "token"), backend.port, ["*.foo", "solo"])
    await out.wait_for("ready: http://solo")
    assert await out.wait_for("connected as") == "connected as ci"
    results = await asyncio.gather(*(get(running.http_port, f"h{i}.foo.{DOMAIN}", f"/{i}") for i in range(20)))
    assert results == [(200, f"GET /{i} HTTP/1.1".encode()) for i in range(20)]
    big = b"x" * 3_000_000
    head = f"POST /big HTTP/1.1\r\nHost: solo.{DOMAIN}\r\nContent-Length: {len(big)}\r\n\r\n".encode()
    response = await http(running.http_port, head + big)
    assert response.endswith(b"POST /big HTTP/1.1")
    await stop(task)
    await asyncio.sleep(0.2)
    assert (await get(running.http_port, f"a.foo.{DOMAIN}"))[0] == 404
    assert running.server.ctx.registry.names() == []


async def test_unreachable_local_port_is_bad_gateway(
    start_server: StartServer, credentials: Credentials, ws_env
) -> None:
    running = await start_server(**ws_env)
    task, out = start_client(running, client_config(credentials, "key"), 9, ["app"])
    await out.wait_for("ready:")
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 502
    await stop(task)


async def test_invalid_names_are_rejected(start_server: StartServer, credentials: Credentials, ws_env) -> None:
    running = await start_server(**ws_env)
    task, out = start_client(running, client_config(credentials, "key"), 9, ["*.*.foo"])
    assert "only allowed as the leftmost" in await out.wait_for("rejected:")
    assert await asyncio.wait_for(task, TIMEOUT) == 1


async def raw_control(running: Running) -> object:
    return await local(running)(f"ws://{DOMAIN}{protocol.CONNECT_PATH}", proxy=None)


@pytest.mark.parametrize(
    ("messages", "reason"),
    [
        (["not json"], "Expecting value"),
        ([json.dumps({"no": "type"})], "not a protocol message"),
        ([protocol.encode("bind", name="x")], "expected hello"),
        ([protocol.encode("hello", method="magic")], "unknown method 'magic'"),
        ([protocol.encode("hello", method="password")], "password"),
        ([protocol.encode("hello", method="key", public_key="ssh-ed25519 nope")], "unreadable public key"),
        (
            [protocol.encode("hello", method="key", public_key="KEY"), protocol.encode("hello")],
            "expected signature",
        ),
        (
            [protocol.encode("hello", method="key", public_key="KEY"), protocol.encode("signature", signature="x")],
            "authentication failed",
        ),
    ],
)
async def test_malformed_logins_are_closed(
    start_server: StartServer, credentials: Credentials, ws_env, messages: list[str], reason: str
) -> None:
    running = await start_server(**ws_env)
    async with await raw_control(running) as ws:
        for message in messages:
            await ws.send(message.replace("KEY", credentials.public_key.strip()))
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
        assert reason in ws.close_reason


async def test_login_must_finish_in_time(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env, WILDBURROW_WEBSOCKET_LOGIN_TIMEOUT="1")
    async with await raw_control(running) as ws:
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
        assert ws.close_code == 4400


async def test_bad_messages_after_login_close_the_session(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env
) -> None:
    running = await start_server(**ws_env)
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        assert protocol.decode(await ws.recv())["type"] == "welcome"
        await ws.send(protocol.encode("bind", name="raw"))
        assert protocol.decode(await ws.recv())["type"] == "bound"
        await ws.send(protocol.encode("open-failed", id="unknown"))
        await ws.send(protocol.encode("bind"))
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
        assert ws.close_code == 4400
    await asyncio.sleep(0.1)
    assert running.server.ctx.registry.names() == []


async def test_streams_need_a_pending_id(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env)
    async with local(running)(f"ws://{DOMAIN}{protocol.DATA_PATH}guess", proxy=None) as ws:
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
        assert ws.close_code == 4404


async def test_client_that_never_opens_the_stream(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env
) -> None:
    running = await start_server(**ws_env, WILDBURROW_WEBSOCKET_OPEN_TIMEOUT="1")
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        await ws.recv()
        await ws.send(protocol.encode("bind", name="lazy"))
        await ws.recv()
        assert (await get(running.http_port, f"lazy.{DOMAIN}"))[0] == 502


async def test_other_root_paths_are_not_found(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env)
    assert (await get(running.http_port, DOMAIN, "/anything"))[0] == 404
    assert (await get(running.http_port, DOMAIN.upper(), "/"))[0] == 404


async def test_root_is_not_found_without_the_websocket_transport(start_server: StartServer) -> None:
    running = await start_server()
    assert (await get(running.http_port, DOMAIN, protocol.CONNECT_PATH))[0] == 404


async def test_password_blocking_uses_the_real_client_address(
    start_server: StartServer, credentials: Credentials, ws_env
) -> None:
    running = await start_server(**ws_env, WILDBURROW_AUTH_PASSWORD_MAX_FAILURES="1")
    task, _ = start_client(running, client_config(credentials, "password"), 9, ["app"], password="wrong")
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    password_auth = running.server.ctx.authenticator._providers[1]
    assert password_auth.blocked("127.0.0.1")
    assert list(password_auth._failures) == ["127.0.0.1"]
    assert running.server.transports[1]._peers == {}


@pytest.mark.acme
async def test_websocket_over_tls(
    start_server: StartServer,
    credentials: Credentials,
    backend: Backend,
    pebble: acme_env.Pebble,
    tls_env: dict[str, str],
    ws_env,
) -> None:
    running = await start_server(**tls_env, **ws_env)
    context = ssl.create_default_context(cadata=await asyncio.to_thread(pebble.root))
    connector = functools.partial(connect, host="127.0.0.1", port=running.https_port, ssl=context)
    config = client_config(credentials, "key", url=f"https://{DOMAIN}")
    async with asyncio.timeout(TIMEOUT):
        while not running.server.ctx.certs.ready(DOMAIN):
            await asyncio.sleep(0.1)
    task, out = start_client(running, config, backend.port, ["*.foo"], connector=connector)
    assert await out.wait_for("ready:") == f"ready: https://*.foo.{DOMAIN}"
    status, _ = await get(running.http_port, DOMAIN, protocol.CONNECT_PATH)
    assert status == 308
    await stop(task)


async def test_cli_subprocess(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env, tmp_path: Path
) -> None:
    running = await start_server(**ws_env, WILDBURROW_DOMAIN="localhost")
    env = os.environ | {"XDG_CONFIG_HOME": str(tmp_path), "WILDBURROW_TOKEN": TOKEN}
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "wildburrow", str(backend.port), "cli",
        "--server", "localhost", "--transport", "websocket", "--auth", "token",
        "--url", f"http://localhost:{running.http_port}", "--local-host", "127.0.0.1",
        stderr=asyncio.subprocess.PIPE, env=env, start_new_session=True,
    )  # fmt: skip
    assert process.stderr is not None
    async with asyncio.timeout(TIMEOUT):
        while not (line := (await process.stderr.readline()).decode()).startswith("ready:"):
            assert line
    assert await get(running.http_port, "cli.localhost") == (200, b"GET / HTTP/1.1")
    process.terminate()
    assert await process.wait() != 0


async def test_disconnect_during_login_and_unknown_messages(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env)
    ws = await raw_control(running)
    await ws.close()
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        await ws.recv()
        await ws.send(protocol.encode("from-the-future"))
        await ws.send(protocol.encode("bind", name="still-works"))
        assert protocol.decode(await ws.recv())["type"] == "bound"


async def test_root_is_bad_gateway_when_the_websocket_server_is_down(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env)
    await running.server.transports[1].stop()
    assert (await get(running.http_port, DOMAIN, protocol.CONNECT_PATH))[0] == 502


async def proxied(running: Running, header: bytes, path: str = protocol.CONNECT_PATH) -> object:
    _, writer = await asyncio.open_connection("127.0.0.1", running.http_port)
    writer.write(header)
    await writer.drain()
    sock = writer.get_extra_info("socket").dup()
    writer.close()
    return await connect(f"ws://{DOMAIN}{path}", sock=sock, proxy=None)


async def test_proxy_protocol_carries_the_visitor_address(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env, WILDBURROW_HTTP_PROXY_PROTOCOL="true")
    async with await proxied(running, b"PROXY TCP4 203.0.113.9 10.0.0.1 51000 80\r\n") as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        await ws.recv()
        await ws.send(protocol.encode("bind", name="app"))
        await ws.recv()
        _, writer = await asyncio.open_connection("127.0.0.1", running.http_port)
        writer.write(b"PROXY TCP4 198.51.100.7 10.0.0.1 40000 80\r\nGET / HTTP/1.1\r\nHost: app." + DOMAIN.encode())
        writer.write(b"\r\n\r\n")
        opened = protocol.decode(await asyncio.wait_for(ws.recv(), TIMEOUT))
        assert opened["type"] == "open"
        assert opened["peer"] == "198.51.100.7"
        writer.close()


async def refused(port: int, raw: bytes) -> bool:
    try:
        return await http(port, raw) == b""
    except ConnectionResetError:
        return True


async def test_proxy_protocol_is_required_and_trusted(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env, WILDBURROW_HTTP_PROXY_PROTOCOL="true")
    assert await refused(running.http_port, f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n".encode())
    untrusted = await start_server(
        **ws_env, WILDBURROW_HTTP_PROXY_PROTOCOL="true", WILDBURROW_PROXY_TRUSTED="10.0.0.0/8"
    )
    header = b"PROXY TCP4 203.0.113.9 10.0.0.1 51000 80\r\n"
    assert await refused(untrusted.http_port, header + f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n".encode())


async def test_password_blocking_follows_the_proxied_address(start_server: StartServer, ws_env) -> None:
    running = await start_server(
        **ws_env, WILDBURROW_HTTP_PROXY_PROTOCOL="true", WILDBURROW_AUTH_PASSWORD_MAX_FAILURES="1"
    )
    async with await proxied(running, b"PROXY TCP4 203.0.113.9 10.0.0.1 51000 80\r\n") as ws:
        await ws.send(protocol.encode("hello", method="password", username="x", password="wrong"))
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
    password_auth = running.server.ctx.authenticator._providers[1]
    assert password_auth.blocked("203.0.113.9")
    assert not password_auth.blocked("127.0.0.1")
