import asyncio
import logging
import os
import signal
import stat
from pathlib import Path

import asyncssh
import pytest
from websockets.exceptions import ConnectionClosedOK
from websockets.frames import Close

from tests.conftest import free_port
from wildburrow import config
from wildburrow.auth.base import Authenticator
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import BindRejected, TunnelUnavailable
from wildburrow.core.types import Peer
from wildburrow.server import Server, serve
from wildburrow.transports.ssh import SSHSettings, SSHTransport, load_host_key
from wildburrow.transports.websocket import WebSocketSettings, WebSocketTransport, _Outbox, _Root, close_reason


def env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    return {
        f"{config.PREFIX}DOMAIN": "tunnel.example.com",
        f"{config.PREFIX}DATA_DIR": str(tmp_path / "data"),
        f"{config.PREFIX}HTTP_HOST": "127.0.0.1",
        f"{config.PREFIX}HTTP_PORT": "0",
        f"{config.PREFIX}SSH_HOST": "127.0.0.1",
        f"{config.PREFIX}SSH_PORT": "0",
        f"{config.PREFIX}AUTH": "password",
        f"{config.PREFIX}AUTH_PASSWORD_HASH": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
        **{f"{config.PREFIX}{key}": value for key, value in overrides.items()},
    }


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"DOMAIN": "bad_domain.com"}, "DOMAIN: 'bad_domain.com' is not a valid domain"),
        ({"DOMAIN": "example.com."}, "is not a valid domain"),
        ({"AUTH": ""}, "need at least one plugin each"),
        ({"TRANSPORTS": ""}, "need at least one plugin each"),
        ({"PROXY_TRUSTED": "10.0.0.0/8,not-a-network"}, "PROXY_TRUSTED: 'not-a-network'"),
    ],
)
def test_invalid_server_settings(tmp_path: Path, overrides: dict[str, str], message: str) -> None:
    values = env(tmp_path, **overrides)
    with pytest.raises(config.ConfigError, match=message):
        Server(config.load(config.ServerSettings, values, config.PREFIX), values)


def test_domain_is_lowercased(tmp_path: Path) -> None:
    values = env(tmp_path, DOMAIN="Tunnel.Example.COM")
    assert Server(config.load(config.ServerSettings, values, config.PREFIX), values).ctx.domain == "tunnel.example.com"


async def test_serve_until_terminated(tmp_path: Path) -> None:
    task = asyncio.create_task(serve(env(tmp_path)))
    while not (tmp_path / "data" / "ssh_host_ed25519_key").exists():
        await asyncio.sleep(0.01)
    os.kill(os.getpid(), signal.SIGTERM)
    await asyncio.wait_for(task, 5)
    assert (tmp_path / "data").stat().st_mode & 0o777 == 0o700


async def test_users_without_a_home_get_the_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_home(cls: type[Path]) -> Path:
        raise RuntimeError("Could not determine home directory.")

    values = env(tmp_path)
    settings = config.load(config.ServerSettings, values, config.PREFIX)
    monkeypatch.delenv("HOME")
    monkeypatch.setattr(Path, "home", classmethod(no_home))
    async with Server(settings, values):
        assert os.environ["HOME"] == str(tmp_path / "data")


async def test_transport_stop_before_start() -> None:
    await SSHTransport(SSHSettings()).stop()
    await WebSocketTransport(WebSocketSettings()).stop()


def test_host_key_is_created_once(tmp_path: Path) -> None:
    path = tmp_path / "key"
    created = load_host_key(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_host_key(path).public_data == created.public_data


@pytest.mark.parametrize(
    ("exc", "reason"),
    [(ValueError("x" * 200), "x" * 100), (KeyError("name"), "'name'"), (TimeoutError(), "TimeoutError")],
)
def test_close_reasons_fit_a_control_frame(exc: Exception, reason: str) -> None:
    assert close_reason(exc) == reason


async def test_the_ssh_server_offers_only_tunnels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    async def create_server(factory: object, host: str, port: int, **options: object) -> object:
        seen.update(host=host, port=port, **options)
        return object()

    monkeypatch.setattr(asyncssh, "create_server", create_server)
    settings = SSHSettings(host="127.0.0.5", port=2200, login_timeout=7, keepalive_interval=9)
    await SSHTransport(settings).start(ServerContext("example.com", 5, tmp_path, Authenticator([])))
    options = ("host", "port", "login_timeout", "keepalive_interval", "allow_scp", "agent_forwarding", "x11_forwarding")
    assert {key: seen[key] for key in options} == {
        "host": "127.0.0.5",
        "port": 2200,
        "login_timeout": 7,
        "keepalive_interval": 9,
        "allow_scp": False,
        "agent_forwarding": False,
        "x11_forwarding": False,
    }


async def test_the_server_listens_where_it_is_told(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    http_port, ssh_port = free_port(), free_port()
    values = env(tmp_path, HTTP_HOST="127.0.0.1", HTTP_PORT=str(http_port), SSH_PORT=str(ssh_port))
    values[f"{config.PREFIX}DATA_DIR"] = str(tmp_path / "nested" / "data")
    async with Server(config.load(config.ServerSettings, values, config.PREFIX), values) as server:
        assert [sock.getsockname()[:2] for sock in server.edges[0]._server.sockets] == [("127.0.0.1", http_port)]
        assert server.transports[0].port == ssh_port
    assert stat.S_IMODE((tmp_path / "nested" / "data").stat().st_mode) == 0o700
    assert ("wildburrow.server", logging.INFO, "serving *.tunnel.example.com") in caplog.record_tuples


async def test_an_unreachable_root_names_the_cause() -> None:
    root = _Root(("127.0.0.1", free_port()), {})
    with pytest.raises(TunnelUnavailable) as error:
        await root.open_stream(Peer("192.0.2.1", 1))
    assert str(error.value) == str(error.value.__cause__)
    assert isinstance(error.value.__cause__, OSError)


async def test_the_outbox_stops_quietly_on_a_closed_connection() -> None:
    class Closed:
        async def send(self, message: str) -> None:
            raise ConnectionClosedOK(Close(1000, ""), None)

    outbox = _Outbox(Closed())
    outbox.put("status", message="x")
    await outbox.flush_and_stop()


async def test_names_are_measured_with_the_domain(tmp_path: Path) -> None:
    domain = "d" * 60 + ".example.com"
    ctx = ServerContext(domain, 5, tmp_path, Authenticator([]))
    name = ".".join(["b" * 60] * 3)
    with pytest.raises(BindRejected, match=rf"^'{name}': longer than 253 characters with the domain$"):
        await ctx.bind(name, object(), print)
