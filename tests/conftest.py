import asyncio
import faulthandler
import os
import socket
import subprocess
import sys
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Generator, Iterator
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from tests import acme_env
from wildburrow import config
from wildburrow.server import Server

DOMAIN = "tunnel.test"
PASSWORD = "correct horse battery staple"
# The names the tests log in under by password.
PASSWORD_USERS = ("tester", "alice")
TIMEOUT = 10


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item: pytest.Item) -> Generator[None]:
    """Ends the run when a teardown hangs, which the test timeout stops watching for once a test has failed."""

    def hung() -> None:
        item.config.pluginmanager.getplugin("capturemanager").suspend_global_capture(in_=True)
        sys.stderr.write(f"\n{item.nodeid} still tearing down after {limit:g}s\n")
        faulthandler.dump_traceback(sys.stderr, all_threads=True)
        os._exit(1)

    limit = float(item.config.getoption("timeout") or item.config.getini("timeout"))
    timer = threading.Timer(limit, hung)
    timer.daemon = True
    timer.start()
    try:
        return (yield)
    finally:
        timer.cancel()


@dataclass(frozen=True)
class Credentials:
    key: Path
    public_key: str
    other_key: Path
    askpass: Path
    wrong_askpass: Path
    password_hash: str = field(repr=False)

    @property
    def password_users(self) -> str:
        """Everyone the tests log in as by password, each with the one test password."""
        return "".join(f"{name}:{self.password_hash}\n" for name in PASSWORD_USERS)


def _keygen(path: Path, comment: str) -> None:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)], check=True)


def _askpass(path: Path, password: str) -> Path:
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{password}'\n")
    path.chmod(0o700)
    return path


@pytest.fixture(scope="session")
def credentials(tmp_path_factory: pytest.TempPathFactory) -> Credentials:
    root = tmp_path_factory.mktemp("credentials")
    _keygen(root / "laptop", "laptop")
    _keygen(root / "stranger", "stranger")
    return Credentials(
        key=root / "laptop",
        public_key=(root / "laptop.pub").read_text(),
        other_key=root / "stranger",
        askpass=_askpass(root / "askpass", PASSWORD),
        wrong_askpass=_askpass(root / "wrong-askpass", "wrong"),
        password_hash=PasswordHasher().hash(PASSWORD),
    )


@pytest.fixture(scope="session")
def pebble(tmp_path_factory: pytest.TempPathFactory) -> Iterator[acme_env.Pebble]:
    workdir = tmp_path_factory.mktemp("pebble")
    env, resources = acme_env.start(workdir)
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("REQUESTS_CA_BUNDLE", str(env.minica))
        patch.syspath_prepend(str(acme_env.register_test_plugins(workdir / "plugins")))
        try:
            yield env
        finally:
            acme_env.stop(resources)


@pytest.fixture
def tls_env(pebble: acme_env.Pebble) -> dict[str, str]:
    return {
        "WILDBURROW_DNS": "challtestsrv",
        "WILDBURROW_DNS_CHALLTESTSRV_URL": pebble.challtestsrv,
        "WILDBURROW_ACME_DIRECTORY": pebble.directory,
        "WILDBURROW_ACME_PROPAGATION_SECONDS": "0",
        "WILDBURROW_ACME_TIMEOUT_SECONDS": "30",
        "WILDBURROW_HTTPS_HOST": "127.0.0.1",
        "WILDBURROW_HTTPS_PORT": "0",
    }


@dataclass
class Running:
    server: Server

    @property
    def http_port(self) -> int:
        return self.server.edges[0].port

    @property
    def https_port(self) -> int:
        return self.server.edges[1].port

    @property
    def ssh_port(self) -> int:
        return self.server.transports[0].port


type StartServer = Callable[..., Awaitable[Running]]


@pytest.fixture
async def start_server(tmp_path: Path, credentials: Credentials) -> AsyncIterator[StartServer]:
    async with AsyncExitStack() as stack:

        async def start(**overrides: str) -> Running:
            env = {
                "WILDBURROW_DOMAIN": DOMAIN,
                "WILDBURROW_DATA_DIR": str(tmp_path / "data"),
                "WILDBURROW_HTTP_HOST": "127.0.0.1",
                "WILDBURROW_HTTP_PORT": "0",
                "WILDBURROW_HEADER_TIMEOUT": "2",
                "WILDBURROW_SSH_HOST": "127.0.0.1",
                "WILDBURROW_SSH_PORT": "0",
                "WILDBURROW_AUTH": "key,password",
                "WILDBURROW_AUTH_KEY_AUTHORIZED_KEYS": credentials.public_key,
                "WILDBURROW_AUTH_PASSWORD_USERS": credentials.password_users,
                **overrides,
            }
            server = Server(config.load(config.ServerSettings, env, config.PREFIX), env)
            return Running(await stack.enter_async_context(server))

        yield start


@dataclass
class Backend:
    port: int
    requests: list[bytes] = field(default_factory=list)


@pytest.fixture
async def backend() -> AsyncIterator[Backend]:
    state = Backend(0)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        state.requests.append(head)
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                await reader.readexactly(int(line.split(b":", 1)[1]))
        body = head.split(b"\r\n", 1)[0]
        writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    state.port = server.sockets[0].getsockname()[1]
    async with server:
        yield state
        # Closing waits on every connection, and one a broken client never closes would hang past the test's timeout.
        server.close_clients()


class SSHClient:
    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process
        self.lines: list[str] = []

    async def line(self, prefix: str) -> str:
        assert self.process.stdout is not None
        async with asyncio.timeout(TIMEOUT):
            while True:
                raw = await self.process.stdout.readline()
                if not raw:
                    raise AssertionError(f"ssh exited before printing {prefix!r}; saw {self.lines}")
                self.lines.append(raw.decode().rstrip("\n"))
                if self.lines[-1].startswith(prefix):
                    return self.lines[-1]

    async def wait(self) -> int:
        async with asyncio.timeout(TIMEOUT):
            return await self.process.wait()

    async def close(self) -> None:
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await self.wait()
            except TimeoutError:
                self.process.kill()
                await self.process.wait()


def ssh_args(port: int, method: str, credentials: Credentials, *, wrong: bool = False) -> tuple[list[str], dict]:
    args = [
        "ssh", "-T", "-F", "/dev/null", "-p", str(port),
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
        "-o", "IdentityAgent=none", "-o", "ConnectTimeout=5",
    ]  # fmt: skip
    env = dict(os.environ)
    if method == "key":
        key = credentials.other_key if wrong else credentials.key
        args += ["-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        args += ["-o", "PreferredAuthentications=publickey"]
    else:
        args += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password"]
        args += ["-o", "NumberOfPasswordPrompts=1"]
        env |= {
            "SSH_ASKPASS": str(credentials.wrong_askpass if wrong else credentials.askpass),
            "SSH_ASKPASS_REQUIRE": "force",
        }
    return args, env


type Connect = Callable[..., Awaitable[SSHClient]]


@pytest.fixture
async def connect(credentials: Credentials) -> AsyncIterator[Connect]:
    clients: list[SSHClient] = []

    async def run(port: int, method: str, *extra: str, wrong: bool = False, command: str = "") -> SSHClient:
        args, env = ssh_args(port, method, credentials, wrong=wrong)
        process = await asyncio.create_subprocess_exec(
            *args,
            *extra,
            "--",
            "tester@127.0.0.1",
            *([command] if command else []),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        clients.append(SSHClient(process))
        return clients[-1]

    yield run
    for client in clients:
        await client.close()


async def http(port: int, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    async with asyncio.timeout(TIMEOUT):
        response = await reader.read()
    writer.close()
    return response


async def get(port: int, host: str, path: str = "/") -> tuple[int, bytes]:
    response = await http(port, f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    status = int(response.split(b" ", 2)[1]) if response else 0
    return status, response.split(b"\r\n\r\n", 1)[-1]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(autouse=True)
def every_record_is_written(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    """The server logs a write it couldn't make and carries on; a test fails on one, since it means a bug."""
    yield
    failed = [record.getMessage() for record in caplog.records if record.name == "wildburrow.store.database"]
    assert failed == []
