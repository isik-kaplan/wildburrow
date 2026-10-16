import asyncio
import contextlib
import logging
import secrets
from dataclasses import dataclass
from http import HTTPStatus

import asyncssh
from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response

from wildburrow import protocol
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import BindRejected, TunnelUnavailable
from wildburrow.core.names import Name
from wildburrow.core.types import (
    Credential,
    Identity,
    PasswordCredential,
    Peer,
    SignedChallengeCredential,
    TokenCredential,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class WebSocketSettings:
    host: str = "127.0.0.1"
    port: int = 0
    login_timeout: int = 30
    open_timeout: int = 10
    max_message_bytes: int = 1 << 20


class ProtocolError(Exception):
    pass


class _Root:
    def __init__(self, host: str, port: int, peers: dict[int, Peer]) -> None:
        self.identity = Identity("wildburrow", "internal", "wildburrow")
        self._host = host
        self._port = port
        self._peers = peers

    async def open_stream(self, peer: Peer) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            reader, writer = await asyncio.open_connection(self._host, self._port)
        except OSError as exc:
            raise TunnelUnavailable(str(exc)) from exc
        self._peers[writer.get_extra_info("sockname")[1]] = peer
        return reader, writer


class _Outbox:
    def __init__(self, connection: ServerConnection) -> None:
        self._queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._task = asyncio.create_task(self._run(connection))

    def put(self, kind: str, **fields: object) -> None:
        self._queue.put_nowait(protocol.encode(kind, **fields))

    async def _run(self, connection: ServerConnection) -> None:
        with contextlib.suppress(ConnectionClosed):
            while (message := await self._queue.get()) is not None:
                await connection.send(message)

    async def flush_and_stop(self) -> None:
        self._queue.put_nowait(None)
        await self._task


class WebSocketTunnel:
    def __init__(self, transport: WebSocketTransport, outbox: _Outbox, identity: Identity) -> None:
        self.identity = identity
        self._transport = transport
        self._outbox = outbox

    async def open_stream(self, peer: Peer) -> tuple[protocol.WebSocketStream, protocol.WebSocketStream]:
        stream_id = secrets.token_urlsafe(24)
        waiter: asyncio.Future[ServerConnection] = asyncio.get_running_loop().create_future()
        self._transport.pending[stream_id] = waiter
        self._outbox.put("open", id=stream_id, peer=peer.host)
        try:
            async with asyncio.timeout(self._transport.settings.open_timeout):
                ws = await waiter
        except TimeoutError:
            raise TunnelUnavailable("the client did not open a stream in time") from None
        finally:
            self._transport.pending.pop(stream_id, None)
        stream = protocol.WebSocketStream(ws)
        return stream, stream


class WebSocketTransport:
    Settings = WebSocketSettings

    def __init__(self, settings: WebSocketSettings) -> None:
        self.settings = settings
        self.pending: dict[str, asyncio.Future[ServerConnection]] = {}
        self._peers: dict[int, Peer] = {}
        self._server: Server | None = None

    async def start(self, ctx: ServerContext) -> None:
        self._ctx = ctx
        self._server = await serve(
            self._handle,
            self.settings.host,
            self.settings.port,
            process_request=self._route,
            max_size=self.settings.max_message_bytes,
            server_header=None,
        )
        host, port = self._server.sockets[0].getsockname()[:2]
        ctx.root = _Root(host, port, self._peers)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _route(self, connection: ServerConnection, request: Request) -> Response | None:
        if request.path == protocol.CONNECT_PATH or request.path.startswith(protocol.DATA_PATH):
            return None
        return connection.respond(HTTPStatus.NOT_FOUND, "not found\n")

    async def _handle(self, connection: ServerConnection) -> None:
        host, port = connection.remote_address[:2]
        peer = self._peers.pop(port, None) or Peer(host, port)
        path = connection.request.path  # type: ignore[union-attr]
        if path == protocol.CONNECT_PATH:
            await self._control(connection, peer)
            return
        waiter = self.pending.get(path.removeprefix(protocol.DATA_PATH))
        if waiter is None or waiter.done():
            await connection.close(protocol.CLOSE_UNKNOWN_STREAM, "unknown stream")
            return
        waiter.set_result(connection)
        await connection.wait_closed()

    async def _control(self, connection: ServerConnection, peer: Peer) -> None:
        try:
            async with asyncio.timeout(self.settings.login_timeout):
                identity = await self._login(connection, peer)
        except ConnectionClosed:
            return
        except (ProtocolError, ValueError, KeyError, TimeoutError) as exc:
            await connection.close(protocol.CLOSE_PROTOCOL_ERROR, str(exc)[:100] or type(exc).__name__)
            return
        if identity is None:
            log.info("websocket login failed from %s", peer.host)
            await connection.close(protocol.CLOSE_AUTH_FAILED, "authentication failed")
            return
        outbox = _Outbox(connection)
        outbox.put("welcome", identity=identity.name)
        tunnel = WebSocketTunnel(self, outbox, identity)
        bound: list[Name] = []
        try:
            async for raw in connection:
                message = protocol.decode(raw)
                if message["type"] == "bind":
                    await self._bind(outbox, tunnel, str(message["name"]), bound)
                elif message["type"] == "open-failed":
                    waiter = self.pending.get(str(message["id"]))
                    if waiter is not None and not waiter.done():
                        waiter.set_exception(TunnelUnavailable("the client could not reach its local port"))
        except ConnectionClosed:
            pass
        except (ValueError, KeyError) as exc:
            await outbox.flush_and_stop()
            await connection.close(protocol.CLOSE_PROTOCOL_ERROR, str(exc)[:100] or type(exc).__name__)
        finally:
            for name in bound:
                self._ctx.registry.unbind(name, tunnel)
            await outbox.flush_and_stop()

    async def _bind(self, outbox: _Outbox, tunnel: WebSocketTunnel, raw: str, bound: list[Name]) -> None:
        try:
            name = await self._ctx.bind(raw, tunnel, lambda text: outbox.put("status", message=text))
        except BindRejected as exc:
            outbox.put("rejected", name=raw, reason=str(exc))
            return
        bound.append(name)
        log.info("%s bound %s over websocket", tunnel.identity.name, name)
        outbox.put("bound", name=str(name), url=self._ctx.url(name))

    async def _login(self, connection: ServerConnection, peer: Peer) -> Identity | None:
        hello = protocol.decode(await connection.recv())
        if hello["type"] != "hello":
            raise ProtocolError("expected hello")
        username = str(hello.get("username", ""))
        credential: Credential
        match hello["method"]:
            case "password":
                credential = PasswordCredential(username, str(hello["password"]))
            case "token":
                credential = TokenCredential(str(hello["token"]))
            case "key":
                credential = await self._challenge(connection, username, str(hello["public_key"]))
            case method:
                raise ProtocolError(f"unknown method {method!r}")
        return await self._ctx.authenticator.authenticate(credential, peer)

    async def _challenge(self, connection: ServerConnection, username: str, key: str) -> SignedChallengeCredential:
        try:
            public_key = asyncssh.import_public_key(key).public_data
        except asyncssh.KeyImportError, ValueError:
            raise ProtocolError("unreadable public key") from None
        message = protocol.challenge_message(self._ctx.domain, secrets.token_urlsafe(32))
        await connection.send(
            protocol.encode("challenge", message=message.decode(), namespace=protocol.SIGNATURE_NAMESPACE)
        )
        answer = protocol.decode(await connection.recv())
        if answer["type"] != "signature":
            raise ProtocolError("expected signature")
        return SignedChallengeCredential(username, public_key, message, str(answer["signature"]))
