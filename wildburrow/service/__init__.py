"""The server as a system service: systemd on Linux, launchd on macOS."""

import os
import pwd
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from wildburrow import envfile
from wildburrow.config import FILE_SUFFIX, PREFIX

NAME = "wildburrow"
CONFIG_DIR = Path("etc/wildburrow")
ENV_FILE = "env"
# Where the service reads its settings, seen from the running system rather than an install root.
ENV_PATH = Path("/") / CONFIG_DIR / ENV_FILE
DATA_DIR = f"{PREFIX}DATA_DIR"
# Installs under these are private to their user, so the service has to run as that user to read its own code.
HOMES = (Path("/home"), Path("/root"), Path("/Users"))
# Present only while systemd runs the system.
SYSTEMD_RUNNING = Path("run/systemd/system")


class ServiceError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Account:
    """Who the service runs as: `name` None is a throwaway user the service manager makes up."""

    name: str | None
    uid: int = 0
    gid: int = 0


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603


def checked(*command: str) -> str:
    result = run(*command)
    if result.returncode != 0:
        raise ServiceError(f"`{' '.join(command)}` failed: {(result.stderr or result.stdout).strip()}")
    return result.stdout


def own(path: Path, account: Account) -> None:
    if account.name is not None and (account.uid, account.gid) != (os.geteuid(), os.getegid()):
        os.chown(path, account.uid, account.gid)


def install_account(prefixes: tuple[str, ...] = (sys.prefix, sys.base_prefix)) -> Account:
    resolved = [Path(prefix).resolve() for prefix in prefixes]
    if not any(path.is_relative_to(home) for path in resolved for home in HOMES):
        return Account(None)
    owner = pwd.getpwuid(Path(prefixes[0]).stat().st_uid)
    return Account(owner.pw_name, owner.pw_uid, owner.pw_gid)


def command() -> list[str]:
    return [sys.executable, "-m", NAME, "serve"]


class Manager(Protocol):
    kind: str
    root: Path

    def data_dirs(self) -> list[Path]: ...

    def installed(self) -> bool: ...

    def install(self, account: Account) -> None: ...

    def uninstall(self) -> None: ...

    def restart(self) -> None: ...

    def status(self) -> str: ...

    def logs(self) -> str: ...

    def file_owner(self, account: Account) -> Account: ...


class Config:
    """The settings a service runs with, kept in one directory only the service and root can read."""

    def __init__(self, manager: Manager) -> None:
        self.manager = manager
        self.dir = manager.root / CONFIG_DIR
        self.env = self.dir / ENV_FILE

    def load(self) -> dict[str, str]:
        settings = envfile.read(self.env)
        for var in [var for var in settings if var.endswith(FILE_SUFFIX)]:
            path = Path(settings[var])
            if path.parent == self.dir:
                settings[var.removesuffix(FILE_SUFFIX)] = path.read_text().removesuffix("\n")
                del settings[var]
        return settings

    def save(self, settings: dict[str, str], account: Account) -> None:
        """Values that span lines, like authorized keys, go in files of their own beside the rest."""
        owner = self.manager.file_owner(account)
        self.dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        for stale in self.dir.iterdir():
            stale.unlink()
        single = {}
        for var, value in settings.items():
            if envfile.fits(value):
                single[var] = value
                continue
            path = self.dir / var.removeprefix(PREFIX).lower()
            path.write_text(value + "\n")
            path.chmod(0o644)
            own(path, owner)
            single[var + FILE_SUFFIX] = str(path)
        envfile.write(self.env, single, 0o600)
        own(self.env, owner)

    def remove(self) -> None:
        if self.dir.exists():
            for path in self.dir.iterdir():
                path.unlink()
            self.dir.rmdir()


def manager(root: Path = Path("/")) -> Manager:
    if sys.platform == "darwin":
        from wildburrow.service.launchd import Launchd

        return Launchd(root)
    if sys.platform.startswith("linux") and (root / SYSTEMD_RUNNING).is_dir():
        from wildburrow.service.systemd import Systemd

        return Systemd(root)
    raise ServiceError("services need systemd (Linux) or launchd (macOS); run `wildburrow serve` some other way")
