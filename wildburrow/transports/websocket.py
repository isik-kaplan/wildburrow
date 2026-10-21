import asyncio
import contextlib
import logging
import secrets
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, ClassVar

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

# A close reason has to fit a control frame.
MAX_REASON = 100
NONCE_BYTES = 32
STREAM_ID_BYTES = 24


@dataclass(frozen=True, slots=True)
class WebSocketSettings:
    host: str = "127.0.0.1"
    port: int = 0
    login_timeout: int = 30
    open_timeout: int = 10
    max_message_bytes: int = 1 << 20


class ProtocolError(Exception):
    pass


def _names(message: dict[str, Any]) -> list[str]:
    # A 0.1 client binds one name per message.
    if "name" in message:
        return [str(message["name"])]
    names = message["names"]
    if not isinstance(names, list) or not names:
        raise ValueError("names must be a list of names")
    return [str(name) for name in names]


def close_reason(exc: Exception) -> str:
    return str(exc)[:MAX_REASON] or type(exc).__name__


class _Root:
    def __init__(self, address: tuple[str, int], peers: dict[int, Peer]) -> None:
        self._address = address
        self._peers = peers

    async def open_stream(self, peer: Peer) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            reader, writer = await asyncio.open_connection(*self._address)
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
        stream_id = secrets.token_urlsafe(STREAM_ID_BYTES)
        waiter: asyncio.Future[ServerConnection] = asyncio.get_running_loop().create_future()
        self._transport.pending[stream_id] = waiter
        self._outbox.put("open", id=stream_id, peer=peer.host)
        try:
            async with asyncio.timeout(self._transport.settings.open_timeout):
                ws = await waiter
        except TimeoutError:
            raise TunnelUnavailable("the client did not open a stream in time") from None
        finally:
            del self._transport.pending[stream_id]
        stream = protocol.WebSocketStream(ws)
        return stream, stream


class WebSocketTransport:
    Settings = WebSocketSettings
    methods: ClassVar[dict[str, type]] = {
        "key": SignedChallengeCredential,
        "password": PasswordCredential,
        "token": TokenCredential,
    }

    def __init__(self, settings: WebSocketSettings) -> None:
        self.settings = settings
        self.pending: dict[str, asyncio.Future[ServerConnection]] = {}
        self._peers: dict[int, Peer] = {}
        self._server: Server | None = None

    def published(self) -> dict[str, int]:
        return {}

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
        ctx.root = _Root(self._server.sockets[0].getsockname()[:2], self._peers)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _route(self, connection: ServerConnection, request: Request) -> Response | None:
        if request.path == protocol.CONNECT_PATH or request.path.startswith(protocol.DATA_PATH):
            return None
        return connection.respond(HTTPStatus.NOT_FOUND, "not found\n")

    async def _handle(self, connection: ServerConnection) -> None:
        address = connection.remote_address[:2]
        peer = self._peers.pop(address[1], None) or Peer(*address)
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
            await connection.close(protocol.CLOSE_PROTOCOL_ERROR, close_reason(exc))
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
                    await self._bind(outbox, tunnel, _names(message), bound)
                elif message["type"] == "names":
                    held = self._ctx.registry.holders().items()
                    names = [{"name": str(name), "yours": holder.identity == identity} for name, holder in held]
                    outbox.put("names", names=names)
                elif message["type"] == "open-failed":
                    waiter = self.pending.get(str(message["id"]))
                    if waiter is not None and not waiter.done():
                        waiter.set_exception(TunnelUnavailable("the client could not reach its local port"))
        except ConnectionClosed:
            pass
        except (ValueError, KeyError) as exc:
            await outbox.flush_and_stop()
            await connection.close(protocol.CLOSE_PROTOCOL_ERROR, close_reason(exc))
        finally:
            for name in bound:
                self._ctx.registry.unbind(name, tunnel)
            await outbox.flush_and_stop()

    async def _bind(self, outbox: _Outbox, tunnel: WebSocketTunnel, raws: list[str], bound: list[Name]) -> None:
        try:
            names = await self._ctx.bind_all(raws, tunnel, lambda text: outbox.put("status", message=text))
        except BindRejected as exc:
            outbox.put("rejected", names=raws, reason=str(exc))
            return
        for name in names:
            bound.append(name)
            log.info("%s bound %s over websocket", tunnel.identity.name, name)
            outbox.put("bound", name=str(name), url=self._ctx.url(name))

    async def _login(self, connection: ServerConnection, peer: Peer) -> Identity | None:
        hello = protocol.decode(await connection.recv())
        if hello["type"] != "hello":
            raise ProtocolError("expected hello")
        credential: Credential
        match hello["method"]:
            case "password":
                credential = PasswordCredential(str(hello["username"]), str(hello["password"]))
            case "token":
                credential = TokenCredential(str(hello["token"]))
            case "key":
                credential = await self._challenge(connection, str(hello["public_key"]))
            case method:
                raise ProtocolError(f"unknown method {method!r}")
        return await self._ctx.authenticator.authenticate(credential, peer)

    async def _challenge(self, connection: ServerConnection, key: str) -> SignedChallengeCredential:
        try:
            public_key = asyncssh.import_public_key(key).public_data
        except asyncssh.KeyImportError, ValueError:
            raise ProtocolError("unreadable public key") from None
        # token_urlsafe(None) would ask for the default of 32 bytes, so that mutant is the same program.
        nonce = secrets.token_urlsafe(NONCE_BYTES)  # pragma: no mutate
        message = protocol.challenge_message(self._ctx.domain, nonce)
        await connection.send(
            protocol.encode("challenge", message=message.decode(), namespace=protocol.SIGNATURE_NAMESPACE)
        )
        answer = protocol.decode(await connection.recv())
        if answer["type"] != "signature":
            raise ProtocolError("expected signature")
        return SignedChallengeCredential(public_key, message, str(answer["signature"]))
