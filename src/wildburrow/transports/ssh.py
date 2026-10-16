import logging
import os
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from wildburrow import protocol
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import BindRejected, TunnelUnavailable
from wildburrow.core.names import Name
from wildburrow.core.registry import Registry
from wildburrow.core.types import Identity, PasswordCredential, Peer, PublicKeyCredential

log = logging.getLogger(__name__)

HOST_KEY_FILE = "ssh_host_ed25519_key"
UNNAMED = {"", "localhost"}


@dataclass(frozen=True, slots=True)
class SSHSettings:
    host: str = "0.0.0.0"  # noqa: S104
    port: int = 2222
    login_timeout: int = 30
    keepalive_interval: int = 30


def load_host_key(path: Path) -> asyncssh.SSHKey:
    if path.exists():
        return asyncssh.read_private_key(path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    path.touch(mode=0o600)
    key.write_private_key(path)
    return key


class SSHTunnel:
    def __init__(self, conn: asyncssh.SSHServerConnection, identity: Identity, host: str, port: int) -> None:
        self.identity = identity
        self._conn = conn
        self._host = host
        self._port = port

    async def open_stream(self, peer: Peer) -> tuple[asyncssh.SSHReader, asyncssh.SSHWriter]:
        try:
            return await self._conn.open_connection(self._host, self._port, peer.host, peer.port)
        except (asyncssh.ChannelOpenError, OSError) as exc:
            raise TunnelUnavailable(str(exc)) from exc


class _Listener(asyncssh.SSHListener):
    def __init__(self, registry: Registry, name: Name, tunnel: SSHTunnel, port: int) -> None:
        super().__init__()
        self._registry = registry
        self._name = name
        self._binding = tunnel
        self._port = port

    def get_port(self) -> int:
        return self._port

    def close(self) -> None:
        self._registry.unbind(self._name, self._binding)


class _Client(asyncssh.SSHServer):
    def __init__(self, ctx: ServerContext, live: set[asyncssh.SSHServerConnection]) -> None:
        self._ctx = ctx
        self._live = live
        self._identity: Identity | None = None
        self._closed = False
        self._pending: list[str] = []
        self._process: asyncssh.SSHServerProcess | None = None
        self._rejected = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        self._live.add(conn)
        self._peer = Peer(*conn.get_extra_info("peername")[:2])

    def connection_lost(self, exc: Exception | None) -> None:
        self._closed = True
        self._live.discard(self._conn)

    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return self._ctx.authenticator.accepts(PublicKeyCredential)

    async def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        return await self._check(PublicKeyCredential(username, key.public_data))

    def password_auth_supported(self) -> bool:
        return self._ctx.authenticator.accepts(PasswordCredential)

    async def validate_password(self, username: str, password: str) -> bool:
        return await self._check(PasswordCredential(username, password))

    async def _check(self, credential: PublicKeyCredential | PasswordCredential) -> bool:
        identity = await self._ctx.authenticator.authenticate(credential, self._peer)
        if identity is None:
            log.info("auth failed for %s from %s", credential.username, self._peer.host)
            return False
        self._identity = identity
        return True

    async def server_requested(self, listen_host: str, listen_port: int) -> _Listener | bool:
        assert self._identity is not None  # noqa: S101
        if listen_host in UNNAMED:
            self.reject("give the tunnel a name, e.g. -R myapp:80:localhost:3000")
            return False
        port = listen_port or 80
        tunnel = SSHTunnel(self._conn, self._identity, listen_host, port)
        try:
            name = await self._ctx.bind(listen_host, tunnel, self.notify)
        except BindRejected as exc:
            self.reject(f"rejected: {exc}")
            return False
        if self._closed:
            self._ctx.registry.unbind(name, tunnel)
            # The connection is gone, so nothing reads this answer.
            return False  # pragma: no mutate
        log.info("%s bound %s from %s", self._identity.name, name, self._peer.host)
        self.notify(f"{protocol.READY}{self._ctx.url(name)}")
        return _Listener(self._ctx.registry, name, tunnel, port)

    def notify(self, message: str) -> None:
        if self._process is None:
            self._pending.append(message)
        else:
            self._process.stdout.write(f"{message}\n")

    # ssh can exit on a refused forward before printing data it already received, so a rejection
    # ends the session instead: closing the channel makes ssh print everything before it exits.
    def reject(self, message: str) -> None:
        self.notify(message)
        self._rejected = True
        if self._process is not None:
            self._process.exit(1)

    def attach(self, process: asyncssh.SSHServerProcess) -> None:
        self._process = process
        for message in self._pending:
            process.stdout.write(f"{message}\n")
        self._pending.clear()
        if self._rejected:
            process.exit(1)


async def _session(process: asyncssh.SSHServerProcess) -> None:
    client: _Client = process.get_extra_info("connection").get_owner()
    client.attach(process)
    # stdin EOF doesn't end the session, so clients started without a terminal (ssh -n, -f, services) stay up.
    await process.stdin.read()
    await process.wait_closed()


class SSHTransport:
    Settings = SSHSettings

    def __init__(self, settings: SSHSettings) -> None:
        self.settings = settings
        self._server: asyncssh.SSHAcceptor | None = None
        self._live: set[asyncssh.SSHServerConnection] = set()

    @property
    def port(self) -> int:
        assert self._server is not None  # noqa: S101
        return self._server.sockets[0].getsockname()[1]

    async def start(self, ctx: ServerContext) -> None:
        # asyncssh expands ~ for every connection, which fails for users without a home (systemd DynamicUser).
        try:
            Path.home()
        except RuntimeError:
            os.environ["HOME"] = str(ctx.data_dir)
        self._server = await asyncssh.create_server(
            lambda: _Client(ctx, self._live),
            self.settings.host,
            self.settings.port,
            server_host_keys=[load_host_key(ctx.data_dir / HOST_KEY_FILE)],
            process_factory=_session,
            login_timeout=self.settings.login_timeout,
            keepalive_interval=self.settings.keepalive_interval,
            allow_scp=False,
            agent_forwarding=False,
            x11_forwarding=False,
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            for conn in list(self._live):
                conn.close()
                await conn.wait_closed()
            await self._server.wait_closed()
