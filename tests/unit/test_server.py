import asyncio
import os
import signal
from pathlib import Path

import pytest

from wildburrow import config
from wildburrow.server import Server, serve
from wildburrow.transports.ssh import SSHSettings, SSHTransport, load_host_key
from wildburrow.transports.websocket import WebSocketSettings, WebSocketTransport


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


async def test_transport_stop_before_start() -> None:
    await SSHTransport(SSHSettings()).stop()
    await WebSocketTransport(WebSocketSettings()).stop()


def test_host_key_is_created_once(tmp_path: Path) -> None:
    path = tmp_path / "key"
    created = load_host_key(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_host_key(path).public_data == created.public_data
