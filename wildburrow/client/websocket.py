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
from wildburrow.client.retry import Backoff
from wildburrow.streams import relay

DEFAULT_IDENTITIES = ("id_ed25519", "id_ecdsa", "id_rsa")
FATAL_CLOSE_CODES = {protocol.CLOSE_PROTOCOL_ERROR, protocol.CLOSE_AUTH_FAILED}


class ClientError(Exception):
    pass


def websocket_base(config: ClientConfig) -> str:
    base = config.url or f"https://{config.server}"
    if base.startswith("https://"):
        return "wss://" + base.removeprefix("https://").removesuffix("/")
    if base.startswith("http://"):
        return "ws://" + base.removeprefix("http://").removesuffix("/")
    raise ClientError(f"url must start with https:// or http://, got {base!r}")


def identity_file(identity: str) -> Path:
    return Path(identity).expanduser() if identity else default_identity()


def default_identity() -> Path:
    for name in DEFAULT_IDENTITIES:
        if (path := Path.home() / ".ssh" / name).exists():
            return path
    raise ClientError("no SSH key found; set one with `wildburrow login --identity PATH`")


def sign(key: Path, namespace: str, message: bytes) -> str:
    command = ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace]
    result = subprocess.run(command, input=message, capture_output=True)  # noqa: S603
    if result.returncode != 0:
        raise ClientError(f"ssh-keygen could not sign: {result.stderr.decode().strip()}")
    return result.stdout.decode()


def hello(config: ClientConfig, ask: Callable[[str], str]) -> dict[str, str]:
    match config.auth:
        case "key":
            public = identity_file(config.identity).with_suffix(".pub")
            return {"method": "key", "username": config.username, "public_key": public.read_text().strip()}
        case "password":
            return {"method": "password", "username": config.username, "password": ask("password: ")}
        case "token":
            if not config.token:
                raise ClientError("no token configured; set one with `wildburrow login --token TOKEN`")
            return {"method": "token", "token": config.token}
        case other:
            raise ClientError(f"unknown auth method {other!r}")


async def login(control: ClientConnection, config: ClientConfig, greeting: dict[str, str]) -> dict[str, Any]:
    """Logs in on `control` and returns the server's welcome, naming the identity it knows this client by."""
    await control.send(protocol.encode("hello", **greeting))
    first = protocol.decode(await control.recv())
    if first["type"] == "challenge":
        signature = sign(identity_file(config.identity), str(first["namespace"]), str(first["message"]).encode())
        await control.send(protocol.encode("signature", signature=signature))
        first = protocol.decode(await control.recv())
    return first


async def ask_server(
    config: ClientConfig,
    request: str,
    answer: str,
    ask: Callable[[str], str] | None = None,
    connector: Callable[..., Any] | None = None,
    feature: str | None = None,
    **fields: str,
) -> dict[str, Any]:
    """Logs in as a tunnel would, sends a `request` message with `fields`, and returns the first `answer`."""
    greeting = hello(config, ask or getpass.getpass)
    try:
        async with (connector or connect)(f"{websocket_base(config)}{protocol.CONNECT_PATH}") as control:
            welcome = await login(control, config, greeting)
            if feature is not None and feature not in welcome.get("features", ()):
                raise ClientError(f"{config.server} runs an older wildburrow; this needs 0.3.0 or later")
            await control.send(protocol.encode(request, **fields))
            async for raw in control:
                if (message := protocol.decode(raw))["type"] == answer:
                    return message
    except ConnectionClosed as exc:
        raise ClientError(
            exc.rcvd.reason if exc.rcvd is not None and exc.rcvd.reason else "connection closed"
        ) from None
    except (OSError, InvalidHandshake, InvalidURI, TimeoutError) as exc:
        raise ClientError(f"could not connect to {websocket_base(config)}: {exc}") from None
    raise ClientError("the server closed the connection without answering")


async def held_names(
    config: ClientConfig, ask: Callable[[str], str] | None = None, connector: Callable[..., Any] | None = None
) -> list[dict[str, Any]]:
    """The names bound on the server right now, each marked whether this client's identity holds it."""
    return list((await ask_server(config, "names", "names", ask, connector))["names"])


async def sessions(
    config: ClientConfig, ask: Callable[[str], str] | None = None, connector: Callable[..., Any] | None = None
) -> list[dict[str, Any]]:
    """The other sessions on the server this client's identity may see."""
    answer = await ask_server(config, protocol.SESSIONS, protocol.SESSIONS, ask, connector, protocol.SESSIONS)
    return list(answer[protocol.SESSIONS])


async def kick(
    config: ClientConfig,
    target: dict[str, str],
    ask: Callable[[str], str] | None = None,
    connector: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Ends the sessions `target` picks by `session`, `name` or `who`: what was ended, and the ids refused."""
    return await ask_server(config, "kick", "kicked", ask, connector, protocol.SESSIONS, **target)


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
        backoff: Backoff | None = None,
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
        self._backoff = backoff or Backoff(config.retry_delay, config.retry_max)
        self._connected = False

    async def run(self) -> int:
        try:
            greeting = hello(self._config, self._ask)
            while True:
                try:
                    async with self._connect(f"{self._base}{protocol.CONNECT_PATH}") as control:
                        if (code := await self._session(control, greeting)) is not None:
                            return code
                    reason = "the server closed the connection"
                except ConnectionClosed as exc:
                    if exc.rcvd is not None and exc.rcvd.code == protocol.CLOSE_ENDED:
                        self._out(f"{protocol.ENDED}{exc.rcvd.reason}")
                        return 1
                    if exc.rcvd is not None and exc.rcvd.code in FATAL_CLOSE_CODES:
                        raise ClientError(exc.rcvd.reason or f"closed with code {exc.rcvd.code}") from None
                    reason = exc.rcvd.reason if exc.rcvd is not None and exc.rcvd.reason else "connection closed"
                except (OSError, InvalidHandshake, TimeoutError) as exc:
                    reason = str(exc) or type(exc).__name__
                state = "connection lost" if self._connected else f"could not connect to {self._base}"
                if not self._config.reconnect:
                    raise ClientError(f"{state}: {reason}")
                delay = self._backoff.next()
                self._out(f"{state}: {reason}; retrying in {delay:g}s")
                await asyncio.sleep(delay)
        except ClientError as exc:
            self._out(f"error: {exc}")
            return 1
        except InvalidURI as exc:
            self._out(f"error: {exc}")
            return 1
        finally:
            for task in self._streams:
                task.cancel()

    async def _session(self, control: ClientConnection, greeting: dict[str, str]) -> int | None:
        self._out(f"connected as {(await login(control, self._config, greeting))['identity']}")
        self._connected = True
        self._backoff.reset()
        await control.send(protocol.encode("bind", names=self._names))
        async for raw in control:
            message = protocol.decode(raw)
            match message["type"]:
                case "status":
                    self._out(str(message["message"]))
                case "bound":
                    self._out(f"{protocol.READY}{message['url']}")
                case "rejected":
                    self._out(f"rejected: {message['reason']}")
                    return 1
                case "open":
                    task = asyncio.create_task(self._stream(control, str(message["id"])))
                    self._streams.add(task)
                    task.add_done_callback(self._streams.discard)
        return None

    async def _stream(self, control: ClientConnection, stream_id: str) -> None:
        try:
            local = await asyncio.open_connection(self._local_host, self._port)
        except OSError:
            with contextlib.suppress(ConnectionClosed):
                await control.send(protocol.encode("open-failed", id=stream_id))
            return
        try:
            data = await self._connect(f"{self._base}{protocol.DATA_PATH}{stream_id}")
        except OSError, InvalidHandshake:
            local[1].close()
            return
        stream = protocol.WebSocketStream(data)
        await relay(local, (stream, stream))
        await data.close()


def run(
    config: ClientConfig, port: int, names: Sequence[str], local_host: str, ask: Callable[[str], str] = getpass.getpass
) -> int:
    client = Client(config, port, names, local_host, ask, out=lambda line: print(line, file=sys.stderr))
    try:
        return asyncio.run(client.run())
    except KeyboardInterrupt:
        return 130
