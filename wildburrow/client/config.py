import getpass
import json
import os
import tomllib
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

# json escapes astral characters as surrogate pairs, which TOML rejects, and leaves DEL raw, which TOML also rejects.
TOML_STRING = json.JSONEncoder(ensure_ascii=False)
TOML_ESCAPES = {0x7F: "\\u007f"}


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "wildburrow" / "config.toml"


@dataclass(frozen=True, slots=True)
class ClientConfig:
    server: str
    ssh_port: int = 2222
    user: str = ""
    transport: str = "ssh"
    auth: str = "key"
    identity: str = ""
    token: str = ""
    url: str = ""
    reconnect: bool = True
    retry_delay: float = 1.0
    retry_max: float = 30.0

    @property
    def username(self) -> str:
        return username(self.user)


def username(user: str) -> str:
    return user or getpass.getuser()


# The settings a login saves; anything else in the file is a client setting saved with `wildburrow config set`.
LOGIN = frozenset(field.name for field in fields(ClientConfig))


def read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as file:
        return tomllib.load(file)


def write_toml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = "".join(f"{key} = {_toml_value(value)}\n" for key, value in data.items())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(lines.encode())
    path.chmod(0o600)


def read_config(path: Path) -> ClientConfig | None:
    """The saved login; None when there is none, though other settings may be saved."""
    data = read_toml(path)
    if "server" not in data:
        return None
    return ClientConfig(**{key: value for key, value in data.items() if key in LOGIN})


def write_config(path: Path, config: ClientConfig) -> None:
    """Saves `config` as the login, keeping every other setting saved."""
    kept = {key: value for key, value in read_toml(path).items() if key not in LOGIN}
    write_toml(path, {**asdict(config), **kept})


def forget_login(path: Path) -> None:
    """Drops the saved login, keeping every other setting saved."""
    kept = {key: value for key, value in read_toml(path).items() if key not in LOGIN}
    if kept:
        write_toml(path, kept)
    else:
        path.unlink()


def _toml_value(value: str | int | float | bool) -> str:
    return TOML_STRING.encode(value).translate(TOML_ESCAPES)
