import asyncio
from pathlib import Path

import pytest
from websockets.exceptions import ConnectionClosedOK
from websockets.frames import Close

from wildburrow import protocol
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig
from wildburrow.client.websocket import Client, ClientError, hello, identity_file, sign, websocket_base


@pytest.mark.parametrize(
    ("config", "base"),
    [
        (ClientConfig("tunnel.example.com"), "wss://tunnel.example.com"),
        (ClientConfig("s", url="https://other.example.com:8443/"), "wss://other.example.com:8443"),
        (ClientConfig("s", url="http://localhost:8000"), "ws://localhost:8000"),
    ],
)
def test_websocket_base(config: ClientConfig, base: str) -> None:
    assert websocket_base(config) == base


def test_websocket_base_rejects_other_schemes() -> None:
    with pytest.raises(ClientError, match="must start with https:// or http://"):
        websocket_base(ClientConfig("s", url="ftp://x"))


def test_identity_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert identity_file(ClientConfig("s", identity="~/k")) == tmp_path / "k"
    with pytest.raises(ClientError, match="no SSH key found"):
        identity_file(ClientConfig("s"))
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ecdsa").touch()
    assert identity_file(ClientConfig("s")) == tmp_path / ".ssh" / "id_ecdsa"
    (tmp_path / ".ssh" / "id_ed25519").touch()
    assert identity_file(ClientConfig("s")) == tmp_path / ".ssh" / "id_ed25519"


def test_sign_reports_ssh_keygen_errors(tmp_path: Path) -> None:
    with pytest.raises(ClientError, match="could not sign"):
        sign(tmp_path / "missing", "wildburrow", b"m")


def test_hello_messages(tmp_path: Path) -> None:
    (tmp_path / "key.pub").write_text("ssh-ed25519 AAAA laptop\n")
    key = ClientConfig("s", user="me", auth="key", identity=str(tmp_path / "key"))
    assert hello(key, input) == {"method": "key", "username": "me", "public_key": "ssh-ed25519 AAAA laptop"}
    password = ClientConfig("s", user="me", auth="password")
    assert hello(password, lambda prompt: "pw") == {"method": "password", "username": "me", "password": "pw"}
    assert hello(ClientConfig("s", auth="token", token="t"), input) == {"method": "token", "token": "t"}
    with pytest.raises(ClientError, match="no token configured"):
        hello(ClientConfig("s", auth="token"), input)
    with pytest.raises(ClientError, match="unknown auth method 'magic'"):
        hello(ClientConfig("s", auth="magic"), input)


class FakeControl:
    def __init__(self, incoming: list[str], hold: asyncio.Event | None = None) -> None:
        self.incoming = incoming
        self.sent: list[dict] = []
        self.hold = hold

    async def __aenter__(self) -> FakeControl:
        return self

    async def __aexit__(self, *exc: object) -> None:
        pass

    async def send(self, message: str) -> None:
        self.sent.append(protocol.decode(message))

    async def recv(self) -> str:
        return self.incoming.pop(0)

    def __aiter__(self) -> FakeControl:
        return self

    async def __anext__(self) -> str:
        if not self.incoming:
            if self.hold is not None:
                await self.hold.wait()
            raise StopAsyncIteration
        return self.incoming.pop(0)


def fake_connector(control: FakeControl, data_error: Exception | None = None):
    def connector(url: str, **kwargs):
        if url.endswith(protocol.CONNECT_PATH):
            return control

        async def data():
            raise data_error

        return data()

    return connector


async def run_client(control: FakeControl, port: int = 9, **kwargs) -> tuple[int, list[str]]:
    lines: list[str] = []
    config = ClientConfig("s", auth="token", token="t", url="http://s")
    client = Client(config, port, ["app"], "127.0.0.1", out=lines.append, connector=fake_connector(control, **kwargs))
    return await client.run(), lines


async def test_unknown_messages_are_ignored_and_closing_ends_the_session() -> None:
    control = FakeControl(
        [
            protocol.encode("welcome", identity="ci"),
            protocol.encode("future-feature"),
            protocol.encode("bound", name="app", url="http://app.s"),
        ]
    )
    assert await run_client(control) == (0, ["connected as ci", "ready: http://app.s"])
    assert control.sent == [{"type": "hello", "method": "token", "token": "t"}, {"type": "bind", "name": "app"}]


async def test_local_port_failures_are_reported(unused_tcp_port: int) -> None:
    hold = asyncio.Event()
    control = FakeControl([protocol.encode("welcome", identity="ci"), protocol.encode("open", id="s1")], hold)
    session = asyncio.create_task(run_client(control, port=unused_tcp_port))
    async with asyncio.timeout(5):
        while not control.sent or control.sent[-1]["type"] != "open-failed":
            await asyncio.sleep(0.01)
    assert control.sent[-1] == {"type": "open-failed", "id": "s1"}
    hold.set()
    await session


async def test_data_connection_failures_close_the_local_socket() -> None:
    accepted = asyncio.Event()

    async def local(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.set()
        assert await reader.read() == b""
        writer.close()

    server = await asyncio.start_server(local, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    hold = asyncio.Event()
    control = FakeControl([protocol.encode("welcome", identity="ci"), protocol.encode("open", id="s1")], hold)
    async with server:
        lines: list[str] = []
        config = ClientConfig("s", auth="token", token="t", url="http://s")
        connector = fake_connector(control, data_error=OSError("refused"))
        client = Client(config, port, ["app"], "127.0.0.1", out=lines.append, connector=connector)
        session = asyncio.create_task(client.run())
        await asyncio.wait_for(accepted.wait(), 5)
        await asyncio.sleep(0.05)
        hold.set()
        await session


async def test_client_errors_are_printed() -> None:
    lines: list[str] = []
    client = Client(ClientConfig("s", auth="token", url="http://s"), 9, ["a"], "127.0.0.1", out=lines.append)
    assert await client.run() == 1
    assert lines == ["error: no token configured; set one with `wildburrow login --token TOKEN`"]


async def test_connection_errors_are_printed(unused_tcp_port: int) -> None:
    lines: list[str] = []
    config = ClientConfig("s", auth="token", token="t", url=f"http://127.0.0.1:{unused_tcp_port}")
    assert await Client(config, 9, ["a"], "127.0.0.1", out=lines.append).run() == 1
    assert lines[0].startswith(f"error: connection to ws://127.0.0.1:{unused_tcp_port} failed:")


async def test_connection_errors_without_a_message_name_the_error() -> None:
    def reset(url: str, **kwargs):
        raise ConnectionResetError

    lines: list[str] = []
    config = ClientConfig("s", auth="token", token="t", url="https://s")
    assert await Client(config, 9, ["a"], "127.0.0.1", out=lines.append, connector=reset).run() == 1
    assert lines == ["error: connection to wss://s failed: ConnectionResetError"]


@pytest.mark.parametrize(
    ("close", "line"),
    [
        (Close(4401, "authentication failed"), "error: authentication failed"),
        (Close(1000, ""), "error: connection to ws://s closed"),
        (None, "error: connection to ws://s closed"),
    ],
)
async def test_server_closes_are_explained(close: Close | None, line: str) -> None:
    class Closing(FakeControl):
        async def recv(self) -> str:
            raise ConnectionClosedOK(close, None)

    assert await run_client(Closing([])) == (1, [line])


def test_run_prints_to_stderr(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    config = ClientConfig("s", auth="token", url="http://s")
    assert websocket.run(config, 9, ["a"], "127.0.0.1") == 1
    assert "no token configured" in capsys.readouterr().err

    async def interrupted(self) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(Client, "run", interrupted)
    assert websocket.run(config, 9, ["a"], "127.0.0.1") == 130


class FakeWS:
    def __init__(self, incoming: list[bytes | str | Exception]) -> None:
        self.incoming = incoming
        self.sent: list[bytes | str] = []
        self.closes = 0
        self.fail_send = False

    async def recv(self) -> bytes | str:
        item = self.incoming.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def send(self, message: bytes | str) -> None:
        if self.fail_send:
            raise ConnectionClosedOK(Close(1000, ""), None)
        self.sent.append(message)

    async def close(self) -> None:
        self.closes += 1


async def test_stream_reads_buffers_and_markers() -> None:
    ws = FakeWS([b"hello world", "noise", b"!", protocol.EOF_MARKER])
    stream = protocol.WebSocketStream(ws)
    assert await stream.read(5) == b"hello"
    assert await stream.read() == b" world"
    assert await stream.read(10) == b"!"
    assert await stream.read() == b""
    assert await stream.read() == b""


async def test_stream_treats_a_closed_socket_as_eof() -> None:
    stream = protocol.WebSocketStream(FakeWS([ConnectionClosedOK(Close(1000, ""), None)]))
    assert await stream.read() == b""


async def test_stream_writes_on_drain_and_closes_once() -> None:
    ws = FakeWS([])
    stream = protocol.WebSocketStream(ws)
    stream.write(b"a")
    stream.write(b"b")
    assert ws.sent == []
    assert stream.can_write_eof()
    stream.write_eof()
    await stream.drain()
    assert ws.sent == [b"a", b"b", protocol.EOF_MARKER]
    stream.close()
    stream.close()
    await asyncio.sleep(0)
    assert ws.closes == 1
    ws.fail_send = True
    stream.write(b"c")
    with pytest.raises(BrokenPipeError):
        await stream.drain()


@pytest.mark.parametrize("message", ["[]", '{"type": 1}', "{}"])
def test_decode_rejects_non_messages(message: str) -> None:
    with pytest.raises(ValueError, match="not a protocol message"):
        protocol.decode(message)
