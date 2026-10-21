import asyncio
import getpass
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from websockets.frames import Close

from wildburrow import protocol
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig
from wildburrow.client.retry import Backoff
from wildburrow.client.websocket import Client, ClientError, hello, identity_file, sign, websocket_base

NO_WAIT = Backoff(0, 0)


@pytest.mark.parametrize(
    ("config", "base"),
    [
        (ClientConfig("tunnel.example.com"), "wss://tunnel.example.com"),
        (ClientConfig("s", url="https://other.example.com:8443/"), "wss://other.example.com:8443"),
        (ClientConfig("s", url="http://localhost:8000"), "ws://localhost:8000"),
        (ClientConfig("s", url="http://box/"), "ws://box"),
    ],
)
def test_websocket_base(config: ClientConfig, base: str) -> None:
    assert websocket_base(config) == base


def test_websocket_base_rejects_other_schemes() -> None:
    with pytest.raises(ClientError, match="must start with https:// or http://"):
        websocket_base(ClientConfig("s", url="ftp://x"))


def test_identity_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert identity_file("~/k") == tmp_path / "k"
    with pytest.raises(ClientError, match=r"^no SSH key found; set one with `wildburrow login --identity PATH`$"):
        identity_file("")
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ecdsa").touch()
    assert identity_file("") == tmp_path / ".ssh" / "id_ecdsa"
    (tmp_path / ".ssh" / "id_ed25519").touch()
    assert identity_file("") == tmp_path / ".ssh" / "id_ed25519"


def test_sign_reports_ssh_keygen_errors(tmp_path: Path) -> None:
    with pytest.raises(ClientError, match="could not sign"):
        sign(tmp_path / "missing", "wildburrow", b"m")


def test_hello_messages(tmp_path: Path) -> None:
    (tmp_path / "key.pub").write_text("ssh-ed25519 AAAA laptop\n")
    key = ClientConfig("s", user="me", auth="key", identity=str(tmp_path / "key"))
    assert hello(key, input) == {"method": "key", "username": "me", "public_key": "ssh-ed25519 AAAA laptop"}
    password = ClientConfig("s", user="me", auth="password")
    prompts: list[str] = []
    assert hello(password, lambda prompt: prompts.append(prompt) or "pw") == {
        "method": "password",
        "username": "me",
        "password": "pw",
    }
    assert prompts == ["password: "]
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


AUTH_FAILED = Close(4401, "authentication failed")


class Refused(FakeControl):
    def __init__(self, close: Close | None = AUTH_FAILED) -> None:
        super().__init__([])
        self.close = close

    async def recv(self) -> str:
        raise ConnectionClosedError(self.close, None)


def fake_connector(*controls: FakeControl | Exception, data_error: Exception | None = None):
    queue = [*controls, Refused()]

    def connector(url: str, **kwargs):
        if url.endswith(protocol.CONNECT_PATH):
            if isinstance(queue[0], Exception):
                raise queue.pop(0)
            return queue.pop(0)

        async def data():
            raise data_error

        return data()

    return connector


def client(port: int, lines: list[str], connector, backoff: Backoff | None = None) -> Client:
    config = ClientConfig("s", auth="token", token="t", url="http://s")
    return Client(config, port, ["app"], "127.0.0.1", out=lines.append, connector=connector, backoff=backoff or NO_WAIT)


async def run_client(*controls: FakeControl | Exception, port: int = 9) -> tuple[int, list[str]]:
    lines: list[str] = []
    return await client(port, lines, fake_connector(*controls)).run(), lines


def welcome() -> str:
    return protocol.encode("welcome", identity="ci")


async def test_unknown_messages_are_ignored_and_a_closed_session_reconnects() -> None:
    control = FakeControl([welcome(), protocol.encode("future-feature"), protocol.encode("bound", name="app", url="u")])
    assert await run_client(control) == (
        1,
        [
            "connected as ci",
            "ready: u",
            "connection lost: the server closed the connection; retrying in 0s",
            "error: authentication failed",
        ],
    )
    assert control.sent == [{"type": "hello", "method": "token", "token": "t"}, {"type": "bind", "names": ["app"]}]


async def test_rejections_end_the_client() -> None:
    control = FakeControl([welcome(), protocol.encode("rejected", reason="app is already bound by bob")])
    assert await run_client(control) == (1, ["connected as ci", "rejected: app is already bound by bob"])


async def test_local_port_failures_are_reported(unused_tcp_port: int) -> None:
    hold = asyncio.Event()
    control = FakeControl([welcome(), protocol.encode("open", id="s1")], hold)
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
    hold = asyncio.Event()
    control = FakeControl([welcome(), protocol.encode("open", id="s1")], hold)
    async with server:
        connector = fake_connector(control, data_error=OSError("refused"))
        session = asyncio.create_task(client(server.sockets[0].getsockname()[1], [], connector).run())
        await asyncio.wait_for(accepted.wait(), 5)
        await asyncio.sleep(0.05)
        hold.set()
        await session


async def test_client_errors_are_printed() -> None:
    lines: list[str] = []
    client = Client(ClientConfig("s", auth="token", url="http://s"), 9, ["a"], "127.0.0.1", out=lines.append)
    assert await client.run() == 1
    assert lines == ["error: no token configured; set one with `wildburrow login --token TOKEN`"]


async def test_bad_urls_are_printed() -> None:
    lines: list[str] = []
    config = ClientConfig("s", auth="token", token="t", url="http://")
    assert await Client(config, 9, ["a"], "127.0.0.1", out=lines.append).run() == 1
    assert lines[0].startswith("error: ")


async def test_unreachable_servers_are_retried(unused_tcp_port: int) -> None:
    lines: list[str] = []
    config = ClientConfig("s", auth="token", token="t", url=f"http://127.0.0.1:{unused_tcp_port}")
    session = asyncio.create_task(Client(config, 9, ["a"], "127.0.0.1", out=lines.append, backoff=NO_WAIT).run())
    async with asyncio.timeout(5):
        while len(lines) < 3:
            await asyncio.sleep(0.01)
    session.cancel()
    with pytest.raises(asyncio.CancelledError):
        await session
    assert all(line.startswith(f"could not connect to ws://127.0.0.1:{unused_tcp_port}: ") for line in lines)
    assert all(line.endswith("; retrying in 0s") for line in lines)


async def test_errors_without_a_message_name_the_error() -> None:
    assert await run_client(ConnectionResetError(), TimeoutError()) == (
        1,
        [
            "could not connect to ws://s: ConnectionResetError; retrying in 0s",
            "could not connect to ws://s: TimeoutError; retrying in 0s",
            "error: authentication failed",
        ],
    )


@pytest.mark.parametrize(
    ("close", "line"),
    [
        (Close(1001, "going away"), "could not connect to ws://s: going away; retrying in 0s"),
        (Close(1006, ""), "could not connect to ws://s: connection closed; retrying in 0s"),
        (None, "could not connect to ws://s: connection closed; retrying in 0s"),
    ],
)
async def test_dropped_connections_are_retried(close: Close | None, line: str) -> None:
    assert await run_client(Refused(close)) == (1, [line, "error: authentication failed"])


@pytest.mark.parametrize(
    ("close", "line"),
    [
        (AUTH_FAILED, "error: authentication failed"),
        (Close(4400, "bad message"), "error: bad message"),
        (Close(4400, ""), "error: closed with code 4400"),
    ],
)
async def test_refusals_are_not_retried(close: Close, line: str) -> None:
    assert await run_client(Refused(close), FakeControl([])) == (1, [line])


async def test_backoff_grows_until_a_login_succeeds() -> None:
    lines: list[str] = []
    session = [welcome()]
    connector = fake_connector(OSError("a"), OSError("b"), FakeControl(session), OSError("c"))
    assert await client(9, lines, connector, Backoff(0.001, 0.002)).run() == 1
    assert lines == [
        "could not connect to ws://s: a; retrying in 0.001s",
        "could not connect to ws://s: b; retrying in 0.002s",
        "connected as ci",
        "connection lost: the server closed the connection; retrying in 0.001s",
        "connection lost: c; retrying in 0.002s",
        "error: authentication failed",
    ]


def test_backoff_doubles_up_to_the_maximum() -> None:
    backoff = Backoff(1, 5)
    assert [backoff.next() for _ in range(5)] == [1, 2, 4, 5, 5]
    backoff.reset()
    assert backoff.next() == 1
    capped = Backoff(10, 3)
    assert [capped.next() for _ in range(2)] == [3, 3]


@pytest.mark.parametrize(
    ("failure", "line"),
    [
        (lambda: OSError("refused"), "error: could not connect to ws://s: refused"),
        (lambda: FakeControl([welcome()]), "error: connection lost: the server closed the connection"),
    ],
)
async def test_reconnecting_can_be_turned_off(failure: Callable[[], FakeControl | Exception], line: str) -> None:
    lines: list[str] = []
    config = ClientConfig("s", auth="token", token="t", url="http://s", reconnect=False)
    client = Client(config, 9, ["app"], "127.0.0.1", out=lines.append, connector=fake_connector(failure()))
    assert await client.run() == 1
    assert lines[-1] == line


def test_backoff_follows_the_config() -> None:
    config = ClientConfig("s", auth="token", token="t", url="http://s", retry_delay=0.5, retry_max=2)
    backoff = Client(config, 9, ["app"], "127.0.0.1")._backoff
    assert [backoff.next() for _ in range(4)] == [0.5, 1, 2, 2]


def test_run_prints_to_stderr(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    config = ClientConfig("s", auth="token", url="http://s")
    assert websocket.run(config, 9, ["a"], "127.0.0.1") == 1
    assert "no token configured" in capsys.readouterr().err

    async def interrupted(self) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(Client, "run", interrupted)
    assert websocket.run(config, 9, ["a"], "127.0.0.1") == 130


def test_run_hands_the_tunnel_to_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []

    class Recording:
        def __init__(self, *args: object, **kwargs: object) -> None:
            seen.append(args)

        async def run(self) -> int:
            return 5

    monkeypatch.setattr(websocket, "Client", Recording)
    config = ClientConfig("s", auth="token", url="http://s")
    assert websocket.run(config, 9, ["a"], "127.0.0.1") == 5
    assert seen == [(config, 9, ["a"], "127.0.0.1")]


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
    assert await stream.read() == b""


async def test_stream_reads_nothing_when_asked_for_nothing() -> None:
    stream = protocol.WebSocketStream(FakeWS([b"abc"]))
    assert await stream.read(0) == b""
    assert await stream.read() == b"abc"


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
    with pytest.raises(BrokenPipeError) as error:
        await stream.drain()
    assert str(error.value) == str(ConnectionClosedOK(Close(1000, ""), None))


@pytest.mark.parametrize("message", ["[]", '{"type": 1}', "{}"])
def test_decode_rejects_non_messages(message: str) -> None:
    with pytest.raises(ValueError, match=r"^not a protocol message$"):
        protocol.decode(message)


async def test_a_stream_relays_the_local_port_over_its_own_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"pong:" + await reader.read(4))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    opened: list[tuple[str, int]] = []
    open_connection = asyncio.open_connection

    async def local(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        opened.append((host, port))
        return await open_connection("127.0.0.1", port)

    monkeypatch.setattr(websocket.asyncio, "open_connection", local)
    hold = asyncio.Event()
    control = FakeControl(
        [welcome(), protocol.encode("status", message="issuing"), protocol.encode("open", id="s1")], hold
    )
    data = FakeWS([b"ping", protocol.EOF_MARKER])
    connections: list[tuple[str, dict]] = []

    def connector(url: str, **kwargs: object) -> object:
        connections.append((url, kwargs))
        if url.endswith(protocol.CONNECT_PATH):
            return control if len(connections) == 1 else Refused()

        async def connect() -> FakeWS:
            return data

        return connect()

    lines: list[str] = []
    config = ClientConfig("s", auth="token", token="t", url="http://s")
    tunnel = Client(config, port, ["app"], "local.test", out=lines.append, connector=connector, backoff=NO_WAIT)
    session = asyncio.create_task(tunnel.run())
    async with server, asyncio.timeout(5):
        while not data.closes or tunnel._streams:
            await asyncio.sleep(0.01)
    hold.set()
    assert await session == 1
    assert opened == [("local.test", port)]
    assert connections[:2] == [
        ("ws://s/_wildburrow/connect", {}),
        ("ws://s/_wildburrow/data/s1", {}),
    ]
    assert data.sent == [b"pong:ping", protocol.EOF_MARKER]
    assert lines[:2] == ["connected as ci", "issuing"]


def test_hello_reads_the_public_half_and_sign_runs_ssh_keygen(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    read: list[str] = []
    monkeypatch.setattr(Path, "read_text", lambda self: read.append(self.name) or "ssh-ed25519 AAAA")
    hello(ClientConfig("s", auth="key", identity=str(tmp_path / "key")), input)
    assert read == ["key.pub"]
    commands: list[list[str]] = []
    monkeypatch.setattr(
        websocket.subprocess,
        "run",
        lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=0, stdout=b"sig"),
    )
    assert sign(tmp_path / "key", "ns", b"m") == "sig"
    assert commands == [["ssh-keygen", "-Y", "sign", "-f", str(tmp_path / "key"), "-n", "ns"]]


async def test_a_stream_that_cannot_reach_its_port_or_the_server_ends_quietly(unused_tcp_port: int) -> None:
    class Gone(FakeControl):
        async def send(self, message: str) -> None:
            raise ConnectionClosedOK(Close(1000, ""), None)

    lines: list[str] = []
    await client(unused_tcp_port, lines, fake_connector())._stream(Gone([]), "s1")


TOKEN_CONFIG = ClientConfig("s", auth="token", token="t", url="http://s")
HELD = [{"name": "app", "yours": True}, {"name": "pic", "yours": False}]


async def test_held_names_logs_in_and_asks_for_them() -> None:
    control = FakeControl([welcome(), protocol.encode("status", message="x"), protocol.encode("names", names=HELD)])
    assert await websocket.held_names(TOKEN_CONFIG, input, fake_connector(control)) == HELD
    assert control.sent == [{"type": "hello", "method": "token", "token": "t"}, {"type": "names"}]


@pytest.mark.parametrize(
    ("control", "message"),
    [
        (Refused, "authentication failed"),
        (lambda: Refused(Close(1000, "")), "connection closed"),
        (lambda: Refused(None), "connection closed"),
        (lambda: FakeControl([welcome()]), "the server closed the connection without listing its names"),
        (lambda: OSError("refused"), "could not connect to ws://s: refused"),
    ],
)
async def test_held_names_says_why_it_has_none(control: Callable[[], FakeControl | Exception], message: str) -> None:
    with pytest.raises(ClientError) as error:
        await websocket.held_names(TOKEN_CONFIG, input, fake_connector(control()))
    assert str(error.value) == message


async def test_held_names_asks_the_password_and_connects_for_real_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    prompts: list[str] = []
    monkeypatch.setattr(getpass, "getpass", lambda prompt: prompts.append(prompt) or "pw")
    monkeypatch.setattr(websocket, "connect", fake_connector(control := FakeControl([welcome()])))
    with pytest.raises(ClientError, match="without listing its names"):
        await websocket.held_names(ClientConfig("s", user="me", auth="password", url="http://s"))
    assert prompts == ["password: "]
    assert control.sent[0] == {"type": "hello", "method": "password", "username": "me", "password": "pw"}
