"""Installs the real service on this machine; run only where sudo needs no password, as on CI runners."""

import asyncio
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.conftest import DOMAIN, TIMEOUT, Backend, Connect, Credentials, free_port, get
from wildburrow import service

pytestmark = pytest.mark.system


def wildburrow(*args: str) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-m", "wildburrow", *args]
    return subprocess.run(command, capture_output=True, text=True, timeout=TIMEOUT, check=False)


def logs() -> str:
    if sys.platform == "darwin":
        command = ["sudo", "cat", "/Library/Logs/wildburrow.log"]
    else:
        command = ["sudo", "journalctl", "-u", "wildburrow", "--no-pager", "-n", "50"]
    return subprocess.run(command, capture_output=True, text=True, check=False).stdout


def exists(path: str) -> bool:
    return subprocess.run(["sudo", "test", "-e", path], check=False).returncode == 0


async def answers(port: int) -> bool:
    try:
        return (await get(port, f"nothing.{DOMAIN}"))[0] == 404
    except ConnectionError:
        return False


async def serving(port: int) -> None:
    async with asyncio.timeout(TIMEOUT):
        while not await answers(port):
            await asyncio.sleep(0.2)


@pytest.fixture
def cleanup() -> Iterator[None]:
    yield
    wildburrow("service", "uninstall", "--yes", "--purge")


async def test_install_edit_and_uninstall_the_service(
    cleanup: None, connect: Connect, credentials: Credentials, backend: Backend, tmp_path: Path
) -> None:
    keys = tmp_path / "authorized_keys"
    keys.write_text(credentials.public_key)
    http_port, ssh_port, new_port = free_port(), free_port(), free_port()
    installed = wildburrow(
        "service", "install", f"--domain={DOMAIN}", "--http-host=127.0.0.1", f"--http-port={http_port}",
        "--ssh-host=127.0.0.1", f"--ssh-port={ssh_port}", f"--auth-key-authorized-keys-file={keys}",
    )  # fmt: skip
    assert installed.returncode == 0, installed.stderr
    assert installed.stderr == "this needs root; asking sudo\n"
    try:
        await serving(http_port)
    except TimeoutError:
        pytest.fail(f"the service never answered:\n{logs()}")

    client = await connect(ssh_port, "key", "-R", f"app:80:127.0.0.1:{backend.port}")
    assert await client.line("ready:") == f"ready: http://app.{DOMAIN}"
    assert await get(http_port, f"app.{DOMAIN}") == (200, b"GET / HTTP/1.1")

    status = wildburrow("service", "status")
    assert status.returncode == 0
    assert status.stdout.splitlines()[0] in {
        "wildburrow is active as a systemd service",
        "wildburrow is running as a launchd service",
    }

    edited = wildburrow("service", "edit", f"--http-port={new_port}")
    assert edited.returncode == 0, edited.stderr
    await serving(new_port)

    removed = wildburrow("service", "uninstall", "--yes", "--purge")
    assert removed.returncode == 0, removed.stderr
    assert removed.stdout == "removed the wildburrow service and its data\n"
    assert not exists(str(service.ENV_PATH.parent))
    assert wildburrow("service", "status").stdout == "not installed\n"
