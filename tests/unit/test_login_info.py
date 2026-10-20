import json
from importlib.metadata import version
from pathlib import Path

import pytest

from tests.conftest import Credentials, get, http
from tests.unit.test_edge import REPLY, Root, running
from wildburrow import config, protocol
from wildburrow.auth.base import Authenticator
from wildburrow.core.context import ServerContext
from wildburrow.core.names import Name
from wildburrow.core.types import Identity, PasswordCredential, PublicKeyCredential, TokenCredential
from wildburrow.edge.http import Mode
from wildburrow.server import Server, client_defaults

DOMAIN = "tunnel.example.com"
INFO = b'{"published": true}'


class Handles:
    def __init__(self, *kinds: type) -> None:
        self.handles = kinds

    async def authenticate(self, credential: object, peer: object) -> None:
        raise NotImplementedError


def test_methods_follow_the_order_providers_are_tried_in() -> None:
    kinds: dict[str, type] = {"key": PublicKeyCredential, "password": PasswordCredential, "token": TokenCredential}
    authenticator = Authenticator([Handles(TokenCredential), Handles(PasswordCredential, PublicKeyCredential)])
    assert authenticator.methods(kinds) == ["token", "key", "password"]
    assert Authenticator([Handles(TokenCredential), Handles(TokenCredential)]).methods(kinds) == ["token"]
    assert Authenticator([Handles(TokenCredential)]).methods({"key": PublicKeyCredential}) == []


def settings(**values: str) -> config.ServerSettings:
    return config.ServerSettings(DOMAIN, **values)  # type: ignore[arg-type]


BOTH = {"ssh": ["key", "password"], "websocket": ["token", "key", "password"]}


@pytest.mark.parametrize(
    ("chosen", "offered", "expected"),
    [
        ({}, BOTH, {"transport": "ssh", "auth": "key"}),
        ({}, {"ssh": [], "websocket": ["token"]}, {"transport": "websocket", "auth": "token"}),
        ({"client_transport": "websocket"}, BOTH, {"transport": "websocket", "auth": "token"}),
        ({"client_auth": "password"}, BOTH, {"transport": "ssh", "auth": "password"}),
        ({"client_transport": "websocket", "client_auth": "key"}, BOTH, {"transport": "websocket", "auth": "key"}),
    ],
)
def test_client_defaults(chosen: dict[str, str], offered: dict[str, list[str]], expected: dict[str, str]) -> None:
    assert client_defaults(settings(**chosen), offered) == expected


@pytest.mark.parametrize(
    ("chosen", "offered", "message"),
    [
        ({}, {"ssh": []}, "no WILDBURROW_AUTH plugin works over any of WILDBURROW_TRANSPORTS"),
        (
            {"client_transport": "websocket"},
            {"ssh": ["key"]},
            "WILDBURROW_CLIENT_TRANSPORT: 'websocket' isn't one of the transports clients can log in over: ssh",
        ),
        (
            {"client_transport": "carrier-pigeon"},
            BOTH,
            "WILDBURROW_CLIENT_TRANSPORT: 'carrier-pigeon' isn't one of the transports clients can log in over: "
            "ssh, websocket",
        ),
        (
            {"client_transport": "ssh"},
            {"ssh": [], "websocket": ["token"]},
            "WILDBURROW_CLIENT_TRANSPORT: 'ssh' isn't one of the transports clients can log in over: websocket",
        ),
        (
            {"client_auth": "token"},
            BOTH,
            "WILDBURROW_CLIENT_AUTH: 'token' doesn't work over ssh, which takes: key, password",
        ),
    ],
)
def test_client_defaults_refuse_what_cannot_log_in(
    chosen: dict[str, str], offered: dict[str, list[str]], message: str
) -> None:
    with pytest.raises(config.ConfigError) as raised:
        client_defaults(settings(**chosen), offered)
    assert str(raised.value) == message


def server_env(tmp_path: Path, credentials: Credentials, **overrides: str) -> dict[str, str]:
    return {
        f"{config.PREFIX}DOMAIN": DOMAIN,
        f"{config.PREFIX}DATA_DIR": str(tmp_path / "data"),
        f"{config.PREFIX}HTTP_HOST": "127.0.0.1",
        f"{config.PREFIX}HTTP_PORT": "0",
        f"{config.PREFIX}SSH_HOST": "127.0.0.1",
        f"{config.PREFIX}SSH_PORT": "0",
        f"{config.PREFIX}TRANSPORTS": "ssh,websocket",
        f"{config.PREFIX}AUTH": "token,password,key",
        f"{config.PREFIX}AUTH_KEY_AUTHORIZED_KEYS": credentials.public_key,
        f"{config.PREFIX}AUTH_PASSWORD_HASH": credentials.password_hash,
        f"{config.PREFIX}AUTH_TOKEN_HASHES": "friend:" + "a" * 64,
        **{f"{config.PREFIX}{key}": value for key, value in overrides.items()},
    }


def server(values: dict[str, str]) -> Server:
    return Server(config.load(config.ServerSettings, values, config.PREFIX), values)


async def test_a_server_publishes_how_to_log_in(tmp_path: Path, credentials: Credentials) -> None:
    async with server(server_env(tmp_path, credentials)) as started:
        ssh_port = started.transports[0].port
        status, body = await get(started.edges[0].port, DOMAIN, protocol.INFO_PATH)
    assert status == 200
    assert json.loads(body) == {
        "version": version("wildburrow"),
        "transports": {
            "ssh": {"auth": ["password", "key"], "port": ssh_port},
            "websocket": {"auth": ["token", "password", "key"]},
        },
        "defaults": {"transport": "ssh", "auth": "password"},
    }


async def test_the_published_ssh_port_can_differ_from_the_bound_one(tmp_path: Path, credentials: Credentials) -> None:
    async with server(server_env(tmp_path, credentials, SSH_PUBLIC_PORT="2200")) as started:
        assert started.transports[0].port != 2200
        assert started.info()["transports"]["ssh"]["port"] == 2200


async def test_the_operator_picks_the_defaults(tmp_path: Path, credentials: Credentials) -> None:
    values = server_env(tmp_path, credentials, CLIENT_TRANSPORT="websocket", CLIENT_AUTH="key")
    async with server(values) as started:
        assert started.info()["defaults"] == {"transport": "websocket", "auth": "key"}


def test_a_default_that_cannot_log_in_stops_the_server(tmp_path: Path, credentials: Credentials) -> None:
    with pytest.raises(config.ConfigError, match="CLIENT_AUTH: 'token' doesn't work over ssh"):
        server(server_env(tmp_path, credentials, CLIENT_TRANSPORT="ssh", CLIENT_AUTH="token"))


async def test_nothing_secret_is_published(tmp_path: Path, credentials: Credentials) -> None:
    async with server(server_env(tmp_path, credentials)) as started:
        published = started.ctx.info.decode()
    secrets = [credentials.password_hash, "friend", "a" * 64, *credentials.public_key.split()]
    assert [secret for secret in secrets if secret in published] == []


@pytest.fixture
def ctx(tmp_path: Path) -> ServerContext:
    ctx = ServerContext(DOMAIN, 5, tmp_path, Authenticator([]))
    ctx.info = INFO
    return ctx


@pytest.mark.parametrize("mode", list(Mode))
@pytest.mark.parametrize("host", [DOMAIN, "127.0.0.1:8080", "other.example.net"])
async def test_any_host_but_a_tunnels_gets_the_document(ctx: ServerContext, host: str, mode: Mode) -> None:
    ctx.root = Root()
    async with running(ctx, mode=mode) as edge:
        reply = await http(edge.port, f"GET {protocol.INFO_PATH} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    head, _, body = reply.partition(b"\r\n\r\n")
    assert head.split(b"\r\n") == [
        b"HTTP/1.1 200 OK",
        f"Content-Length: {len(INFO)}".encode(),
        b"Content-Type: application/json",
        b"Connection: close",
    ]
    assert body == INFO
    assert ctx.root.peers == []


class Bound(Root):
    identity = Identity("someone", "key", "someone")


async def test_a_tunnel_keeps_the_path_for_its_own_app(ctx: ServerContext) -> None:
    async with running(ctx) as edge:
        assert await get(edge.port, f"app.{DOMAIN}", protocol.INFO_PATH) == (404, b"404 Not Found\n")
        ctx.registry.bind(Name(("app",)), tunnel := Bound())
        reply = await http(edge.port, f"GET {protocol.INFO_PATH} HTTP/1.1\r\nHost: app.{DOMAIN}\r\n\r\n".encode())
    assert reply == REPLY
    assert len(tunnel.peers) == 1


async def test_a_host_outside_the_domain_reaches_no_tunnel(ctx: ServerContext) -> None:
    ctx.root = root = Root()
    async with running(ctx) as edge:
        assert await get(edge.port, "127.0.0.1", "/") == (404, b"404 Not Found\n")
    assert root.peers == []


async def test_only_the_exact_path_is_the_document(ctx: ServerContext) -> None:
    ctx.root = root = Root()
    async with running(ctx) as edge:
        reply = await http(edge.port, f"GET {protocol.INFO_PATH}?x HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n".encode())
    assert reply == REPLY
    assert len(root.peers) == 1
