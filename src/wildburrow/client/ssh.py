from collections.abc import Sequence

from wildburrow.client.config import ClientConfig

REMOTE_PORT = 80


def ssh_command(config: ClientConfig, port: int, names: Sequence[str], local_host: str) -> list[str]:
    command = [
        "ssh",
        "-T",
        "-p",
        str(config.ssh_port),
        "-o",
        "ServerAliveInterval=30",
    ]
    for name in names:
        command += ["-R", f"{name}:{REMOTE_PORT}:{local_host}:{port}"]
    command += ["--", f"{config.username}@{config.server}"]
    return command
