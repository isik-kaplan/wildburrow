import asyncio
import json
from typing import Any

from websockets.asyncio.connection import Connection
from websockets.exceptions import ConnectionClosed

CONNECT_PATH = "/_wildburrow/connect"
DATA_PATH = "/_wildburrow/data/"
INFO_PATH = "/_wildburrow/info"
# Where the server's own domain logs visitors in to a locked tunnel with only wildcard names.
LOCK_PATH = "/_wildburrow/lock/"
SIGNATURE_NAMESPACE = "wildburrow"
WEBSOCKET = "websocket"
EOF_MARKER = "eof"
READY = "ready: "
# Printed when the server ends a session on purpose, which the client then doesn't retry.
ENDED = "closed: "
# What a server answers beyond 0.2.0, listed in its welcome, and the release that brought each.
SESSIONS = "sessions"
LOCK = "lock"
INDEX = "index"
DENY = "deny"
USERS = "users"
SINCE = {SESSIONS: "0.3.0", LOCK: "0.4.0", INDEX: "0.5.0", DENY: "0.5.0", USERS: "0.6.0"}
# Sent instead of a hello, by someone setting up the login an invite is for; answered, then closed.
JOIN = "join"
CLOSE_PROTOCOL_ERROR = 4400
CLOSE_AUTH_FAILED = 4401
CLOSE_UNKNOWN_STREAM = 4404
CLOSE_ENDED = 4410


def challenge_message(domain: str, nonce: str) -> bytes:
    return f"wildburrow-login:{domain}:{nonce}".encode()


def encode(kind: str, **fields: Any) -> str:
    return json.dumps({"type": kind, **fields})


def decode(message: str | bytes) -> dict[str, Any]:
    data = json.loads(message)
    if not isinstance(data, dict) or not isinstance(data.get("type"), str):
        raise ValueError("not a protocol message")
    return data


class WebSocketStream:
    def __init__(self, ws: Connection) -> None:
        self._ws = ws
        self._buffer = b""
        self._eof = False
        self._outgoing: list[bytes | str] = []
        self._closing: asyncio.Task[None] | None = None

    async def read(self, n: int = -1) -> bytes:
        while not self._buffer and not self._eof:
            try:
                message = await self._ws.recv()
            except ConnectionClosed:
                self._eof = True
                break
            if message == EOF_MARKER:
                self._eof = True
            elif isinstance(message, bytes):
                self._buffer = message
        size = len(self._buffer) if n < 0 else n
        chunk, self._buffer = self._buffer[:size], self._buffer[size:]
        return chunk

    def write(self, data: bytes) -> None:
        self._outgoing.append(data)

    async def drain(self) -> None:
        while self._outgoing:
            try:
                await self._ws.send(self._outgoing.pop(0))
            except ConnectionClosed as exc:
                raise BrokenPipeError(str(exc)) from exc

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self._outgoing.append(EOF_MARKER)

    def close(self) -> None:
        if self._closing is None:
            self._closing = asyncio.ensure_future(self._ws.close())
