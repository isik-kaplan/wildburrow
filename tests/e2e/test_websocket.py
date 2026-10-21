import asyncio
import contextlib
import functools
import json
import logging
import os
import ssl
import sys
import time
from pathlib import Path

import pytest
from websockets.asyncio.client import connect

from tests import acme_env
from tests.conftest import (
    DOMAIN,
    PASSWORD,
    TIMEOUT,
    Backend,
    Connect,
    Credentials,
    Running,
    StartServer,
    free_port,
    get,
    http,
)
from wildburrow import cli, protocol, tokens
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, read_config
from wildburrow.client.websocket import Client, sign
from wildburrow.tokens import digest, new_token

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


class ConnectProxy:
    def __init__(self, upstream: int) -> None:
        self.upstream = upstream
        self.targets: list[str] = []

    async def __call__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        self.targets.append(head.split()[1].decode())
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", self.upstream)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(ConnectionError):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    writer.close()


async def test_the_client_goes_through_the_proxy_from_the_environment(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    running = await start_server(**ws_env)
    proxy = ConnectProxy(running.http_port)
    server = await asyncio.start_server(proxy, "127.0.0.1", 0)
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("https_proxy", f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}")
    task, out = start_client(running, client_config(credentials, "token"), backend.port, ["app"], connector=connect)
    await out.wait_for("ready:")
    assert await get(running.http_port, f"app.{DOMAIN}", "/p") == (200, b"GET /p HTTP/1.1")
    await stop(task)
    server.close()
    assert proxy.targets == [f"{DOMAIN}:80", f"{DOMAIN}:80"]


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
        (["not json"], "Expecting value: line 1 column 1 (char 0)"),
        ([json.dumps({"no": "type"})], "not a protocol message"),
        ([protocol.encode("bind", name="x")], "expected hello"),
        ([protocol.encode("hello", method="magic")], "unknown method 'magic'"),
        ([protocol.encode("hello", method="password", username="u")], "'password'"),
        ([protocol.encode("hello", method="password", password="p")], "'username'"),
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
        assert ws.close_reason == reason


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
        assert (ws.close_code, ws.close_reason) == (protocol.CLOSE_UNKNOWN_STREAM, "unknown stream")


async def test_client_that_never_opens_the_stream(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    running = await start_server(**ws_env, WILDBURROW_WEBSOCKET_OPEN_TIMEOUT="1")
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        await ws.recv()
        await ws.send(protocol.encode("bind", name="lazy"))
        await ws.recv()
        assert (await get(running.http_port, f"lazy.{DOMAIN}"))[0] == 502
        opened = protocol.decode(await ws.recv())
    assert opened["type"] == "open"
    assert len(opened["id"]) == 32
    assert running.server.transports[1].pending == {}
    message = f"could not reach the client for lazy.{DOMAIN}: the client did not open a stream in time"
    assert ("wildburrow.edge.http", logging.INFO, message) in caplog.record_tuples


async def test_messages_over_the_limit_are_refused(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env, WILDBURROW_WEBSOCKET_MAX_MESSAGE_BYTES="1024")
    async with await raw_control(running) as ws:
        await ws.send("x" * 2000)
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
        assert ws.close_code == 1009


async def direct_login(port: int, host: str) -> tuple[object, object]:
    async with connect(f"ws://{host}:{port}{protocol.CONNECT_PATH}", proxy=None) as ws:
        await ws.send(protocol.encode("hello", method="token", token="wb_wrong"))
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
        return ws.close_code, ws.close_reason


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_the_transport_takes_direct_connections(
    start_server: StartServer, ws_env, host: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    port = free_port()
    running = await start_server(**ws_env, WILDBURROW_WEBSOCKET_HOST=host, WILDBURROW_WEBSOCKET_PORT=str(port))
    assert [sock.getsockname()[:2] for sock in running.server.transports[1]._server.sockets] == [(host, port)]
    assert await direct_login(port, f"[{host}]" if ":" in host else host) == (
        protocol.CLOSE_AUTH_FAILED,
        "authentication failed",
    )
    assert ("wildburrow.transports.websocket", logging.INFO, f"websocket login failed from {host}") in (
        caplog.record_tuples
    )
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        assert protocol.decode(await ws.recv()) == {"type": "welcome", "identity": "ci"}


async def test_other_root_paths_are_not_found(start_server: StartServer, ws_env) -> None:
    running = await start_server(**ws_env)
    response = await http(running.http_port, f"GET /anything HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n".encode())
    assert response.startswith(b"HTTP/1.1 404 ")
    assert response.endswith(b"\r\n\r\nnot found\n")
    assert b"\r\nserver:" not in response.lower()
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
    assert await out.wait_for("issuing") == f"issuing a certificate for *.foo.{DOMAIN}"
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


async def key_challenge(running: Running, credentials: Credentials) -> tuple[object, str]:
    ws = await raw_control(running)
    await ws.send(protocol.encode("hello", method="key", username="tester", public_key=credentials.public_key.strip()))
    challenge = protocol.decode(await ws.recv())
    assert challenge["namespace"] == protocol.SIGNATURE_NAMESPACE
    return ws, str(challenge["message"])


async def test_key_logins_answer_a_fresh_challenge_for_this_server(
    start_server: StartServer, credentials: Credentials, ws_env
) -> None:
    running = await start_server(**ws_env)
    first, message = await key_challenge(running, credentials)
    second, other = await key_challenge(running, credentials)
    prefix, _, nonce = message.rpartition(":")
    assert prefix == f"wildburrow-login:{DOMAIN}"
    assert len(nonce) == 43
    assert other != message
    signature = sign(credentials.key, protocol.SIGNATURE_NAMESPACE, message.encode())
    await second.send(protocol.encode("signature", signature=signature))
    await asyncio.wait_for(second.wait_closed(), TIMEOUT)
    assert (second.close_code, second.close_reason) == (protocol.CLOSE_AUTH_FAILED, "authentication failed")
    await first.send(protocol.encode("signature", signature=signature))
    assert protocol.decode(await first.recv()) == {"type": "welcome", "identity": "laptop"}
    await first.close()


@pytest.mark.parametrize(
    ("hello", "identity"),
    [
        ({"method": "password", "username": "alice", "password": PASSWORD}, "alice"),
        ({"method": "token", "token": TOKEN}, "ci"),
    ],
)
async def test_logins_are_welcomed_by_name(start_server: StartServer, ws_env, hello: dict, identity: str) -> None:
    running = await start_server(**ws_env)
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", **hello))
        assert protocol.decode(await ws.recv()) == {"type": "welcome", "identity": identity}


async def test_binds_are_answered_in_full(start_server: StartServer, ws_env, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    running = await start_server(**ws_env)
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        await ws.recv()
        # The form a 0.1 client sends, one name per message.
        await ws.send(protocol.encode("bind", name="*.*.foo"))
        assert protocol.decode(await ws.recv()) == {
            "type": "rejected",
            "names": ["*.*.foo"],
            "reason": "'*.*.foo': '*' is only allowed as the leftmost label",
        }
        await ws.send(protocol.encode("bind", name="App"))
        assert protocol.decode(await ws.recv()) == {"type": "bound", "name": "app", "url": f"http://app.{DOMAIN}"}
    assert ("wildburrow.transports.websocket", logging.INFO, "ci bound app over websocket") in caplog.record_tuples


async def test_failed_logins_are_logged(start_server: StartServer, ws_env, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    running = await start_server(**ws_env)
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token="wb_wrong"))
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
    assert ("wildburrow.transports.websocket", logging.INFO, "websocket login failed from 127.0.0.1") in (
        caplog.record_tuples
    )


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        (json.dumps({"type": "bind"}), "'names'"),
        (json.dumps({"type": "bind", "names": "app"}), "names must be a list of names"),
        (json.dumps({"type": "bind", "names": []}), "names must be a list of names"),
        ("x" * 200, "Expecting value: line 1 column 1 (char 0)"),
        (json.dumps({"type": "open-failed"}), "'id'"),
    ],
)
async def test_protocol_errors_after_login_name_the_problem(
    start_server: StartServer, ws_env, message: str, reason: str
) -> None:
    running = await start_server(**ws_env)
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        await ws.recv()
        await ws.send(message)
        await asyncio.wait_for(ws.wait_closed(), TIMEOUT)
        assert (ws.close_code, ws.close_reason) == (protocol.CLOSE_PROTOCOL_ERROR, reason)


async def test_an_unreachable_local_port_is_reported(
    start_server: StartServer, credentials: Credentials, ws_env, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    running = await start_server(**ws_env)
    async with await raw_control(running) as ws:
        await ws.send(protocol.encode("hello", method="token", token=TOKEN))
        await ws.recv()
        await ws.send(protocol.encode("bind", name="gone"))
        await ws.recv()
        request = asyncio.create_task(get(running.http_port, f"gone.{DOMAIN}"))
        opened = protocol.decode(await ws.recv())
        await ws.send(protocol.encode("open-failed", id=opened["id"]))
        assert (await request)[0] == 502
    message = f"could not reach the client for gone.{DOMAIN}: the client could not reach its local port"
    assert ("wildburrow.edge.http", logging.INFO, message) in caplog.record_tuples


@pytest.mark.parametrize(
    ("server_auth", "login", "expected"),
    [("key", [], "key"), ("token,key", ["--token", TOKEN], "token")],
)
async def test_login_needs_nothing_but_the_server(
    start_server: StartServer,
    credentials: Credentials,
    backend: Backend,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    server_auth: str,
    login: list[str],
    expected: str,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    running = await start_server(
        WILDBURROW_TRANSPORTS="websocket",
        WILDBURROW_AUTH=server_auth,
        WILDBURROW_AUTH_TOKEN_HASHES=f"ci:{digest(TOKEN)}",
    )
    url = f"http://127.0.0.1:{running.http_port}"
    args = ["login", DOMAIN, "--url", url, "--identity", str(credentials.key), *login]
    assert await asyncio.to_thread(cli.main, args) == 0
    saved = read_config(config_path())
    assert (saved.transport, saved.auth) == ("websocket", expected)
    task, out = start_client(running, saved.__replace__(url=f"http://{DOMAIN}"), backend.port, ["app"])
    assert await out.wait_for("ready:") == f"ready: http://app.{DOMAIN}"
    assert await get(running.http_port, f"app.{DOMAIN}", "/w") == (200, b"GET /w HTTP/1.1")
    await stop(task)


def signed(
    credentials: Credentials, names: tuple[str, ...] | None, expires: int | None = None, who: str = "alice"
) -> str:
    grant = tokens.Grant(who, names, expires, int(time.time()), tokens.new_id())
    return tokens.encode(grant.payload(), tokens.unarmor(sign(credentials.key, tokens.NAMESPACE, grant.payload())))


SIGNED_ENV = {"WILDBURROW_TRANSPORTS": "websocket", "WILDBURROW_AUTH": "token"}


async def test_a_signed_token_opens_only_its_names(
    start_server: StartServer, credentials: Credentials, backend: Backend
) -> None:
    running = await start_server(**SIGNED_ENV, WILDBURROW_AUTH_TOKEN_SIGNERS=credentials.public_key)
    token = signed(credentials, ("alice", "*.alice"))
    config = client_config(credentials, "token", token=token)
    task, out = start_client(running, config, backend.port, ["alice", "*.alice"])
    assert await out.wait_for("connected as") == "connected as alice"
    assert await out.wait_for("ready:") == f"ready: http://alice.{DOMAIN}"
    assert await get(running.http_port, f"api.alice.{DOMAIN}", "/w") == (200, b"GET /w HTTP/1.1")
    await stop(task)
    refused, out = start_client(running, config, backend.port, ["alice", "bob"])
    assert await asyncio.wait_for(refused, TIMEOUT) == 1
    assert await out.wait_for("rejected:") == "rejected: bob: alice may only claim alice, *.alice"
    assert running.server.ctx.registry.names() == []


async def test_an_expired_token_is_refused(start_server: StartServer, credentials: Credentials) -> None:
    running = await start_server(**SIGNED_ENV, WILDBURROW_AUTH_TOKEN_SIGNERS=credentials.public_key)
    config = client_config(credentials, "token", token=signed(credentials, None, int(time.time()) - 3600))
    task, out = start_client(running, config, 9, ["app"])
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert await out.wait_for("error:") == "error: authentication failed"


async def test_a_bind_takes_every_name_or_none(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env
) -> None:
    running = await start_server(**ws_env)
    holder, out = start_client(running, client_config(credentials, "key"), backend.port, ["taken", "pic"])
    await out.wait_for("ready:")
    task, out = start_client(running, client_config(credentials, "token"), backend.port, ["free", "taken", "pic"])
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert await out.wait_for("rejected:") == (
        "rejected: taken is already bound by laptop; pic is already bound by laptop"
    )
    assert sorted(map(str, running.server.ctx.registry.names())) == ["pic", "taken"]
    await stop(holder)


async def test_names_lists_what_is_bound_and_whose(
    start_server: StartServer, credentials: Credentials, backend: Backend, ws_env
) -> None:
    running = await start_server(**ws_env)
    holder, out = start_client(running, client_config(credentials, "key"), backend.port, ["mine", "*.mine"])
    await out.wait_for("ready:")
    await out.wait_for("ready:")
    connector = local(running)
    assert sorted(
        await websocket.held_names(client_config(credentials, "key"), connector=connector), key=lambda e: e["name"]
    ) == [{"name": "*.mine", "yours": True}, {"name": "mine", "yours": True}]
    assert await websocket.held_names(client_config(credentials, "token"), connector=connector) == [
        {"name": "mine", "yours": False},
        {"name": "*.mine", "yours": False},
    ]
    await stop(holder)
