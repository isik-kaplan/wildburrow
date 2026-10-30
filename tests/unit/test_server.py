import asyncio
import dataclasses
import logging
import os
import signal
import socket
import stat
from pathlib import Path

import asyncssh
import pytest
from websockets.exceptions import ConnectionClosedOK
from websockets.frames import Close

from tests.conftest import free_port
from tests.unit.test_registry import FakeTunnel
from wildburrow import config
from wildburrow import server as server_module
from wildburrow.auth.base import Authenticator
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import BindRejected, TunnelUnavailable
from wildburrow.core.types import Identity, Peer
from wildburrow.server import Server, serve
from wildburrow.transports.ssh import SSHSettings, SSHTransport, load_host_key
from wildburrow.transports.websocket import (
    WebSocketSettings,
    WebSocketTransport,
    _Outbox,
    _Root,
    close_reason,
    recorded,
)


def env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    return {
        f"{config.PREFIX}DOMAIN": "tunnel.example.com",
        f"{config.PREFIX}DATA_DIR": str(tmp_path / "data"),
        f"{config.PREFIX}HTTP_HOST": "127.0.0.1",
        f"{config.PREFIX}HTTP_PORT": "0",
        f"{config.PREFIX}SSH_HOST": "127.0.0.1",
        f"{config.PREFIX}SSH_PORT": "0",
        f"{config.PREFIX}AUTH": "password",
        f"{config.PREFIX}AUTH_PASSWORD_USERS": (
            "alice:$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
        ),
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
        ({"INDEX": "maybe"}, "^WILDBURROW_INDEX: expected one of never, opt-in, opt-out, got 'maybe'$"),
        (
            {"AUTH_PASSWORD_HASH": "$argon2id$x"},
            "^WILDBURROW_AUTH_PASSWORD_HASH: gone in 0.6.0, since one password let anyone log in under any name; give "
            "each user a line in WILDBURROW_AUTH_PASSWORD_USERS from `wildburrow passwords hash NAME`, or invite them "
            "with `wildburrow users invite NAME`$",
        ),
        ({"AUTH_PASSWORD_HASH_FILE": "/h"}, "^WILDBURROW_AUTH_PASSWORD_HASH: gone in 0.6.0"),
    ],
)
def test_invalid_server_settings(tmp_path: Path, overrides: dict[str, str], message: str) -> None:
    values = env(tmp_path, **overrides)
    with pytest.raises(config.ConfigError, match=message):
        Server(config.load(config.ServerSettings, values, config.PREFIX), values)


@dataclasses.dataclass
class WithSecrets:
    name: str = "x"
    key: str = dataclasses.field(default="", metadata={config.SECRET: True})
    other: str = dataclasses.field(default="s3cret", metadata={config.SECRET: True})


def test_a_run_records_its_settings_with_secrets_only_as_set() -> None:
    assert server_module.recorded(WithSecrets()) == {"name": "x", "key": "", "other": "(set)"}  # type: ignore[arg-type]


async def test_the_server_takes_its_log_handler_away_when_it_stops(tmp_path: Path) -> None:
    values = env(tmp_path)
    server = Server(config.load(config.ServerSettings, values, config.PREFIX), values)
    before = list(logging.getLogger("wildburrow").handlers)
    async with server:
        assert len(logging.getLogger("wildburrow").handlers) == len(before) + 1
    assert logging.getLogger("wildburrow").handlers == before


def test_certificates_go_in_the_servers_record(tmp_path: Path) -> None:
    values = env(tmp_path)
    server = Server(config.load(config.ServerSettings, values, config.PREFIX), values)
    server.dns = object()
    assert server._setup_tls()._record is server.ctx.record


def test_domain_is_lowercased(tmp_path: Path) -> None:
    values = env(tmp_path, DOMAIN="Tunnel.Example.COM")
    assert Server(config.load(config.ServerSettings, values, config.PREFIX), values).ctx.domain == "tunnel.example.com"


async def test_serve_until_terminated(tmp_path: Path) -> None:
    task = asyncio.create_task(serve(env(tmp_path)))
    while not (tmp_path / "data" / "ssh_host_ed25519_key").exists():
        assert not task.done(), task.exception()
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
        await ctx.bind(name, FakeTunnel(Identity("a", "key", "a")), print)


class ClosingDNS:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def bindable(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


async def test_a_failed_start_stops_what_already_started(tmp_path: Path) -> None:
    http_port = free_port()
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        values = env(tmp_path, HTTP_PORT=str(http_port), SSH_PORT=str(taken.getsockname()[1]))
        server = Server(config.load(config.ServerSettings, values, config.PREFIX), values)
        with pytest.raises(OSError, match="address already in use"):
            await server.__aenter__()
    assert bindable(http_port)


async def test_a_failed_tls_start_closes_the_dns_plugin(tmp_path: Path) -> None:
    http_port = free_port()
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        values = env(tmp_path, HTTP_PORT=str(http_port), HTTPS_HOST="127.0.0.1", HTTPS_PORT=str(taken.getsockname()[1]))
        server = Server(config.load(config.ServerSettings, values, config.PREFIX), values)
        server.dns = dns = ClosingDNS()
        with pytest.raises(OSError, match="address already in use"):
            await server.__aenter__()
    assert bindable(http_port)
    assert dns.closed
    assert server.transports[0]._server is None


async def test_a_tls_server_shuts_down_cleanly(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    values = env(tmp_path, HTTPS_HOST="127.0.0.1", HTTPS_PORT="0", ACME_DIRECTORY=f"http://127.0.0.1:{free_port()}/")
    server = Server(config.load(config.ServerSettings, values, config.PREFIX), values)
    server.dns = dns = ClosingDNS()
    async with server:
        while "getting the *.tunnel.example.com certificate failed; retrying in 300s" not in caplog.messages:
            await asyncio.sleep(0.01)
    assert dns.closed


@pytest.mark.parametrize(
    ("answer", "kept"),
    [
        ({"label": "l", "url": "https://foo.example.com/_wildburrow/login/link/KEY"},
         {"label": "l", "url": "https://foo.example.com/_wildburrow/login/link/"}),
        ({"url": "https://foo.example.com/x"}, {"url": "https://foo.example.com/x"}),
        ({"names": []}, {"names": []}),
    ],
)  # fmt: skip
def test_a_link_answer_is_recorded_without_its_key(answer: dict, kept: dict) -> None:
    assert recorded(answer) == kept
