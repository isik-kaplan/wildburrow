import asyncio
import contextlib
import logging
import os
import socket
import sys
from pathlib import Path

import asyncssh
import pytest

from tests.conftest import (
    DOMAIN,
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

pytestmark = pytest.mark.e2e

METHODS = ["key", "password"]
SERVER_AUTH = ["key", "password", "key,password", "password,key"]


def forward(name: str, port: int) -> list[str]:
    return ["-R", f"{name}:80:127.0.0.1:{port}"]


@pytest.mark.parametrize("server_auth", SERVER_AUTH)
@pytest.mark.parametrize("method", METHODS)
async def test_auth_matrix(
    start_server: StartServer, connect: Connect, backend: Backend, server_auth: str, method: str
) -> None:
    running = await start_server(WILDBURROW_AUTH=server_auth)
    client = await connect(running.ssh_port, method, *forward("app", backend.port))
    if method in server_auth.split(","):
        assert await client.line("ready:") == f"ready: http://app.{DOMAIN}"
        assert await get(running.http_port, f"app.{DOMAIN}") == (200, b"GET / HTTP/1.1")
    else:
        assert await client.wait() != 0
        assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 404


@pytest.mark.parametrize("method", METHODS)
async def test_wrong_credentials_are_rejected(start_server: StartServer, connect: Connect, method: str) -> None:
    running = await start_server()
    client = await connect(running.ssh_port, method, *forward("app", 9), wrong=True)
    assert await client.wait() == 255
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 404


async def test_password_attempts_are_blocked_per_address(start_server: StartServer, connect: Connect) -> None:
    running = await start_server(WILDBURROW_AUTH="password", WILDBURROW_AUTH_PASSWORD_MAX_FAILURES="2")
    for _ in range(2):
        assert await (await connect(running.ssh_port, "password", wrong=True)).wait() == 255
    client = await connect(running.ssh_port, "password", *forward("app", 9))
    assert await client.wait() == 255


@pytest.mark.parametrize("method", METHODS)
async def test_routing(start_server: StartServer, connect: Connect, backend: Backend, method: str) -> None:
    running = await start_server()
    names = ["*.foo", "*.bar.foo", "api.foo", "solo"]
    client = await connect(running.ssh_port, method, *[arg for name in names for arg in forward(name, backend.port)])
    for name in names:
        await client.line(f"ready: http://{name}.{DOMAIN}")

    for host in ["auth.foo", "bar.foo", "api.foo", "x.bar.foo", "solo", "SOLO"]:
        status, body = await get(running.http_port, f"{host}.{DOMAIN}:80", "/path?q=1")
        assert (status, body) == (200, b"GET /path?q=1 HTTP/1.1")
    for host in ["foo", "x.api.foo", "y.x.bar.foo", "other"]:
        assert (await get(running.http_port, f"{host}.{DOMAIN}"))[0] == 404
    assert (await get(running.http_port, "solo.elsewhere.test"))[0] == 404
    assert backend.requests[0].endswith(b"\r\n\r\n")


@pytest.mark.parametrize("method", METHODS)
async def test_tunnels_outlive_a_closed_stdin(
    start_server: StartServer, connect: Connect, backend: Backend, method: str
) -> None:
    running = await start_server()
    client = await connect(running.ssh_port, method, "-n", *forward("app", backend.port))
    await client.line("ready:")
    await asyncio.sleep(0.5)
    assert client.process.returncode is None
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 200


@pytest.mark.parametrize("method", METHODS)
async def test_names_are_released_on_disconnect(
    start_server: StartServer, connect: Connect, backend: Backend, method: str
) -> None:
    running = await start_server()
    first = await connect(running.ssh_port, method, *forward("*.foo", backend.port))
    await first.line("ready:")
    assert (await get(running.http_port, f"a.foo.{DOMAIN}"))[0] == 200
    await first.close()
    await asyncio.sleep(0.2)
    assert (await get(running.http_port, f"a.foo.{DOMAIN}"))[0] == 404
    second = await connect(running.ssh_port, method, *forward("*.foo", backend.port))
    await second.line("ready:")


@pytest.mark.parametrize(("first", "second"), [("key", "password"), ("password", "key")])
async def test_taken_name_is_refused(
    start_server: StartServer, connect: Connect, backend: Backend, first: str, second: str
) -> None:
    running = await start_server()
    holder = await connect(running.ssh_port, first, *forward("*.foo", backend.port))
    await holder.line("ready:")
    other = await connect(running.ssh_port, second, *forward("*.foo", 9))
    assert (await other.line("rejected:")).startswith("rejected: *.foo is already bound by ")
    assert await other.wait() == 1
    assert (await get(running.http_port, f"a.foo.{DOMAIN}"))[0] == 200


@pytest.mark.parametrize("method", METHODS)
async def test_the_same_identity_moves_a_name(
    start_server: StartServer, connect: Connect, backend: Backend, method: str
) -> None:
    running = await start_server()
    old = await connect(running.ssh_port, method, *forward("*.foo", 9))
    await old.line("ready:")
    new = await connect(running.ssh_port, method, *forward("*.foo", backend.port))
    await new.line("ready:")
    assert (await get(running.http_port, f"a.foo.{DOMAIN}"))[0] == 200
    await old.close()
    await asyncio.sleep(0.2)
    assert (await get(running.http_port, f"a.foo.{DOMAIN}"))[0] == 200


@pytest.mark.parametrize("name", ["*.*.foo", "a..b", "-a", "a_b", "*", "a.b.c.d.e.f", "localhost", ""])
async def test_invalid_names_are_refused(start_server: StartServer, connect: Connect, name: str) -> None:
    running = await start_server()
    client = await connect(running.ssh_port, "key", "-R", f"{name}:80:127.0.0.1:9" if name else "80:127.0.0.1:9")
    assert await client.wait() != 0


async def test_unreachable_local_port_is_bad_gateway(start_server: StartServer, connect: Connect) -> None:
    running = await start_server()
    client = await connect(running.ssh_port, "key", *forward("app", 9))
    await client.line("ready:")
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 502


async def test_local_forwarding_is_refused(start_server: StartServer, connect: Connect, backend: Backend) -> None:
    running = await start_server()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        local_port = probe.getsockname()[1]
    client = await connect(running.ssh_port, "key", "-L", f"{local_port}:127.0.0.1:{backend.port}", "-N")
    async with asyncio.timeout(TIMEOUT):
        while True:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
                break
            except OSError:
                await asyncio.sleep(0.05)
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    with contextlib.suppress(ConnectionResetError):
        assert await reader.read() == b""
    writer.close()
    assert client.process.returncode is None
    assert backend.requests == []


async def test_commands_are_not_executed(start_server: StartServer, connect: Connect, tmp_path) -> None:
    running = await start_server()
    marker = tmp_path / "ran"
    client = await connect(running.ssh_port, "key", *forward("app", 9), command=f"touch {marker}")
    await client.line("ready:")
    await asyncio.sleep(0.2)
    assert not marker.exists()


async def test_host_key_persists_across_restarts(start_server: StartServer, tmp_path) -> None:
    first = await start_server()
    key_file = tmp_path / "data" / "ssh_host_ed25519_key"
    created = key_file.read_bytes()
    assert key_file.stat().st_mode & 0o777 == 0o600
    await start_server(WILDBURROW_SSH_PORT="0")
    assert key_file.read_bytes() == created
    assert first.ssh_port


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (b"GET / HTTP/1.1\r\nHost: app.tunnel.test\r\nHost: other.tunnel.test\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\n\r\n", 400),
        (b"GET http://app.tunnel.test/ HTTP/1.1\r\nHost: app.tunnel.test\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nHost: app.tunnel.test\r\nX: " + b"a" * 70000 + b"\r\n\r\n", 431),
    ],
)
async def test_malformed_requests_are_rejected(
    start_server: StartServer, connect: Connect, backend: Backend, raw: bytes, status: int
) -> None:
    running = await start_server()
    client = await connect(running.ssh_port, "key", *forward("app", backend.port))
    await client.line("ready:")
    response = await http(running.http_port, raw)
    assert response.startswith(f"HTTP/1.1 {status} ".encode())
    assert backend.requests == []


async def test_slow_request_head_times_out(start_server: StartServer) -> None:
    running = await start_server()
    response = await http(running.http_port, b"GET / HTTP/1.1\r\n")
    assert response.startswith(b"HTTP/1.1 408 ")


async def test_truncated_request_head_is_dropped(start_server: StartServer) -> None:
    running = await start_server()
    reader, writer = await asyncio.open_connection("127.0.0.1", running.http_port)
    writer.write(b"GET / HTTP/1.1\r\n")
    writer.write_eof()
    assert await reader.read() == b""
    writer.close()


async def test_dynamic_remote_port(start_server: StartServer, connect: Connect, backend: Backend) -> None:
    running = await start_server()
    client = await connect(running.ssh_port, "key", "-R", f"app:0:127.0.0.1:{backend.port}")
    await client.line("ready:")
    assert (await get(running.http_port, f"app.{DOMAIN}"))[0] == 200


def ssh_session(running: Running, credentials: Credentials) -> asyncssh.SSHClientConnection:
    return asyncssh.connect(
        "127.0.0.1",
        running.ssh_port,
        username="tester",
        client_keys=[str(credentials.key)],
        known_hosts=None,
        agent_path=None,
    )


async def test_bind_after_session_is_open(
    start_server: StartServer, credentials: Credentials, backend: Backend
) -> None:
    running = await start_server()
    async with ssh_session(running, credentials) as conn:
        process = await conn.create_process()
        await conn.forward_remote_port("late", 80, "127.0.0.1", backend.port)
        async with asyncio.timeout(TIMEOUT):
            assert await process.stdout.readline() == f"ready: http://late.{DOMAIN}\n"
        assert (await get(running.http_port, f"late.{DOMAIN}"))[0] == 200
        process.stdin.write_eof()
        await asyncio.sleep(0.2)
        assert (await get(running.http_port, f"late.{DOMAIN}"))[0] == 200


@pytest.mark.parametrize("session_first", [True, False])
async def test_rejection_ends_the_session(
    start_server: StartServer, credentials: Credentials, session_first: bool
) -> None:
    running = await start_server()
    async with ssh_session(running, credentials) as conn:
        process = await conn.create_process() if session_first else None
        with pytest.raises(asyncssh.ChannelListenError):
            await conn.forward_remote_port("a..b", 80, "127.0.0.1", 9)
        process = process or await conn.create_process()
        async with asyncio.timeout(TIMEOUT):
            assert (await process.stdout.readline()).startswith("rejected: ")
            assert (await process.wait()).exit_status == 1


async def test_unnamed_forwards_are_refused_with_a_hint(start_server: StartServer, connect: Connect) -> None:
    running = await start_server()
    client = await connect(running.ssh_port, "key", "-R", "80:127.0.0.1:9")
    assert await client.line("give") == "give the tunnel a name, e.g. -R myapp:80:localhost:3000"
    assert await client.wait() == 1


async def test_dynamic_ports_are_reported_as_80(
    start_server: StartServer, credentials: Credentials, backend: Backend
) -> None:
    running = await start_server()
    async with ssh_session(running, credentials) as conn:
        listener = await conn.forward_remote_port("dyn", 0, "127.0.0.1", backend.port)
        assert listener.get_port() == 80
        assert (await get(running.http_port, f"dyn.{DOMAIN}"))[0] == 200


async def test_ssh_logins_must_finish_in_time(start_server: StartServer) -> None:
    running = await start_server(WILDBURROW_SSH_LOGIN_TIMEOUT="1")
    reader, writer = await asyncio.open_connection("127.0.0.1", running.ssh_port)
    async with asyncio.timeout(TIMEOUT):
        assert (await reader.readline()).startswith(b"SSH-2.0-")
        while await reader.read(65536):
            pass
    writer.close()


async def test_ssh_logins_and_binds_are_logged(
    start_server: StartServer, connect: Connect, backend: Backend, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    running = await start_server()
    assert await (await connect(running.ssh_port, "password", wrong=True)).wait() == 255
    client = await connect(running.ssh_port, "key", *forward("app", backend.port))
    await client.line("ready:")
    assert {("wildburrow.transports.ssh", logging.INFO, message) for message in (
        "auth failed for tester from 127.0.0.1", "laptop bound app from 127.0.0.1"
    )} <= set(caplog.record_tuples)  # fmt: skip


async def test_failed_logins_name_the_user_for_every_method(
    start_server: StartServer, credentials: Credentials, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    running = await start_server()
    attempts = [
        {"username": "keyuser", "client_keys": [str(credentials.other_key)], "preferred_auth": "publickey"},
        {"username": "pwuser", "client_keys": None, "password": "wrong", "preferred_auth": "password"},
    ]
    for options in attempts:
        with pytest.raises(asyncssh.PermissionDenied):
            await asyncssh.connect("127.0.0.1", running.ssh_port, known_hosts=None, agent_path=None, **options)
    assert {("wildburrow.transports.ssh", logging.INFO, f"auth failed for {user} from 127.0.0.1") for user in (
        "keyuser", "pwuser"
    )} <= set(caplog.record_tuples)  # fmt: skip


async def test_ipv6_ssh_clients_bind_and_leave_no_trace(
    start_server: StartServer, credentials: Credentials, backend: Backend
) -> None:
    running = await start_server(WILDBURROW_SSH_HOST="::1")
    async with asyncssh.connect(
        "::1",
        running.ssh_port,
        username="tester",
        client_keys=[str(credentials.key)],
        known_hosts=None,
        agent_path=None,
    ) as conn:
        await conn.forward_remote_port("six", 80, "127.0.0.1", backend.port)
        assert (await get(running.http_port, f"six.{DOMAIN}"))[0] == 200
    async with asyncio.timeout(TIMEOUT):
        while running.server.transports[0]._live:
            await asyncio.sleep(0.05)


async def test_forwarded_channels_carry_the_visitor_and_refusals_are_reported(
    start_server: StartServer, credentials: Credentials, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    running = await start_server()
    origins: list[tuple[str, int]] = []

    def session(orig_host: str, orig_port: int) -> None:
        origins.append((orig_host, orig_port))
        raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "nobody home")

    async with ssh_session(running, credentials) as conn:
        await conn.create_server(session, "visited", 80)
        reader, writer = await asyncio.open_connection("127.0.0.1", running.http_port)
        writer.write(f"GET / HTTP/1.1\r\nHost: visited.{DOMAIN}\r\n\r\n".encode())
        async with asyncio.timeout(TIMEOUT):
            assert (await reader.read()).startswith(b"HTTP/1.1 502 ")
        visitor = writer.get_extra_info("sockname")
        writer.close()
    assert origins == [visitor[:2]]
    refusals = [m for name, _, m in caplog.record_tuples if name == "wildburrow.edge.http"]
    assert refusals == [f"could not reach the client for visited.{DOMAIN}: nobody home"]


async def test_an_unnamed_forward_is_refused_to_the_client(start_server: StartServer, credentials: Credentials) -> None:
    running = await start_server()
    async with ssh_session(running, credentials) as conn:
        with pytest.raises(asyncssh.ChannelListenError):
            await conn.forward_remote_port("", 0, "127.0.0.1", 9)


async def test_serve_from_the_command_line_with_the_accounts_keys(
    connect: Connect, credentials: Credentials, backend: Backend, tmp_path: Path
) -> None:
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "authorized_keys").write_text(credentials.public_key)
    env = {key: value for key, value in os.environ.items() if not key.startswith("WILDBURROW_")} | {
        "HOME": str(tmp_path)
    }
    http_port, ssh_port = free_port(), free_port()
    server = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "wildburrow", "serve", f"--domain={DOMAIN}", "--data-dir", str(tmp_path / "data"),
        "--http-host", "127.0.0.1", "--http-port", str(http_port),
        "--ssh-host", "127.0.0.1", "--ssh-port", str(ssh_port),
        stderr=asyncio.subprocess.PIPE, env=env, start_new_session=True,
    )  # fmt: skip
    assert server.stderr is not None
    async with asyncio.timeout(TIMEOUT):
        while not (line := (await server.stderr.readline()).decode()).endswith(f"serving *.{DOMAIN}\n"):
            assert line
    client = await connect(ssh_port, "key", *forward("app", backend.port))
    assert await client.line("ready:") == f"ready: http://app.{DOMAIN}"
    assert await get(http_port, f"app.{DOMAIN}") == (200, b"GET / HTTP/1.1")
    server.terminate()
    assert await server.wait() == 0
