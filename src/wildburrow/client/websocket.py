import asyncio
import contextlib
import getpass
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidURI

from wildburrow import protocol
from wildburrow.client.config import ClientConfig
from wildburrow.streams import relay

DEFAULT_IDENTITIES = ("id_ed25519", "id_ecdsa", "id_rsa")


class ClientError(Exception):
    pass


def websocket_base(config: ClientConfig) -> str:
    base = config.url or f"https://{config.server}"
    if base.startswith("https://"):
        return "wss://" + base.removeprefix("https://").rstrip("/")
    if base.startswith("http://"):
        return "ws://" + base.removeprefix("http://").rstrip("/")
    raise ClientError(f"url must start with https:// or http://, got {base!r}")


def identity_file(config: ClientConfig) -> Path:
    if config.identity:
        return Path(config.identity).expanduser()
    for name in DEFAULT_IDENTITIES:
        if (path := Path.home() / ".ssh" / name).exists():
            return path
    raise ClientError("no SSH key found; set one with `wildburrow login --identity PATH`")


def sign(key: Path, namespace: str, message: bytes) -> str:
    result = subprocess.run(  # noqa: S603
        ["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", namespace],  # noqa: S607
        input=message,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ClientError(f"ssh-keygen could not sign the login challenge: {result.stderr.decode().strip()}")
    return result.stdout.decode()


def hello(config: ClientConfig, ask: Callable[[str], str]) -> dict[str, str]:
    match config.auth:
        case "key":
            public = identity_file(config).with_suffix(".pub")
            return {"method": "key", "username": config.username, "public_key": public.read_text().strip()}
        case "password":
            return {"method": "password", "username": config.username, "password": ask("password: ")}
        case "token":
            if not config.token:
                raise ClientError("no token configured; set one with `wildburrow login --token TOKEN`")
            return {"method": "token", "token": config.token}
        case other:
            raise ClientError(f"unknown auth method {other!r}")


class Client:
    def __init__(
        self,
        config: ClientConfig,
        port: int,
        names: Sequence[str],
        local_host: str,
        ask: Callable[[str], str] = getpass.getpass,
        out: Callable[[str], None] = print,
        connector: Callable[..., Any] = connect,
    ) -> None:
        self._config = config
        self._port = port
        self._names = list(names)
        self._local_host = local_host
        self._ask = ask
        self._out = out
        self._base = websocket_base(config)
        self._streams: set[asyncio.Task[None]] = set()
        self._connect = connector

    async def run(self) -> int:
        try:
            greeting = hello(self._config, self._ask)
            async with self._connect(f"{self._base}{protocol.CONNECT_PATH}", proxy=None) as control:
                return await self._session(control, greeting)
        except ClientError as exc:
            self._out(f"error: {exc}")
            return 1
        except ConnectionClosed as exc:
            if exc.rcvd is None or not exc.rcvd.reason:
                self._out(f"error: connection to {self._base} closed")
            else:
                self._out(f"error: {exc.rcvd.reason}")
            return 1
        except (OSError, InvalidHandshake, InvalidURI) as exc:
            self._out(f"error: connection to {self._base} failed: {str(exc) or type(exc).__name__}")
            return 1
        finally:
            for task in self._streams:
                task.cancel()

    async def _session(self, control: ClientConnection, greeting: dict[str, str]) -> int:
        await control.send(protocol.encode("hello", **greeting))
        first = protocol.decode(await control.recv())
        if first["type"] == "challenge":
            key = identity_file(self._config)
            signature = sign(key, str(first["namespace"]), str(first["message"]).encode())
            await control.send(protocol.encode("signature", signature=signature))
            first = protocol.decode(await control.recv())
        self._out(f"connected as {first['identity']}")
        for name in self._names:
            await control.send(protocol.encode("bind", name=name))
        waiting = set(self._names)
        async for raw in control:
            message = protocol.decode(raw)
            match message["type"]:
                case "status":
                    self._out(str(message["message"]))
                case "bound":
                    self._out(f"ready: {message['url']}")
                    waiting.discard(str(message["name"]))
                case "rejected":
                    self._out(f"rejected: {message['reason']}")
                    return 1
                case "open":
                    task = asyncio.create_task(self._stream(control, str(message["id"])))
                    self._streams.add(task)
                    task.add_done_callback(self._streams.discard)
        return 0

    async def _stream(self, control: ClientConnection, stream_id: str) -> None:
        try:
            local = await asyncio.open_connection(self._local_host, self._port)
        except OSError:
            with contextlib.suppress(ConnectionClosed):
                await control.send(protocol.encode("open-failed", id=stream_id))
            return
        try:
            data = await self._connect(f"{self._base}{protocol.DATA_PATH}{stream_id}", proxy=None)
        except OSError, InvalidHandshake:
            local[1].close()
            return
        stream = protocol.WebSocketStream(data)
        await relay(local, (stream, stream))
        await data.close()


def run(config: ClientConfig, port: int, names: Sequence[str], local_host: str) -> int:
    client = Client(config, port, names, local_host, out=lambda line: print(line, file=sys.stderr))
    try:
        return asyncio.run(client.run())
    except KeyboardInterrupt:
        return 130
