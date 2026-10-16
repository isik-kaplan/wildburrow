import asyncio
import signal
import sys
from collections.abc import Callable, Sequence

from wildburrow import protocol
from wildburrow.client.config import ClientConfig
from wildburrow.client.retry import Backoff

REMOTE_PORT = 80
CONNECTION_FAILED = 255
TERMINATED = 128 + signal.SIGTERM
KEEPALIVE = ("-o", "ServerAliveInterval=30")


def ssh_command(config: ClientConfig, port: int, names: Sequence[str], local_host: str) -> list[str]:
    command = ["ssh", "-T", "-p", str(config.ssh_port), *KEEPALIVE]
    for name in names:
        command += ["-R", f"{name}:{REMOTE_PORT}:{local_host}:{port}"]
    command += ["--", f"{config.username}@{config.server}"]
    return command


# Only a session that came up is retried: ssh exits 255 for refused logins as well as dropped connections.
async def tunnel(
    command: Sequence[str],
    out: Callable[[str], None],
    env: dict[str, str] | None = None,
    backoff: Backoff | None = None,
    reconnect: bool = True,
) -> int:
    backoff = backoff or Backoff()
    connected = False
    while True:
        process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, env=env)
        ready = False
        try:
            assert process.stdout is not None  # noqa: S101
            async for raw in process.stdout:
                line = raw.decode(errors="replace").rstrip("\r\n")
                out(line)
                ready = ready or line.startswith(protocol.READY)
            code = await process.wait()
        finally:
            if process.returncode is None:
                process.terminate()
                await process.wait()
        if ready:
            connected = True
            backoff.reset()
        if code != CONNECTION_FAILED or not connected or not reconnect:
            return code
        delay = backoff.next()
        out(f"connection lost; retrying in {delay:g}s")
        await asyncio.sleep(delay)


async def _main(config: ClientConfig, command: Sequence[str]) -> int:
    task = asyncio.current_task()
    assert task is not None  # noqa: S101
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    out = lambda line: print(line, file=sys.stderr)  # noqa: E731
    try:
        return await tunnel(
            command, out, backoff=Backoff(config.retry_delay, config.retry_max), reconnect=config.reconnect
        )
    except asyncio.CancelledError:
        return TERMINATED


def run(config: ClientConfig, port: int, names: Sequence[str], local_host: str) -> int:
    try:
        return asyncio.run(_main(config, ssh_command(config, port, names, local_host)))
    except KeyboardInterrupt:
        return 130
