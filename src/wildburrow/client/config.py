import getpass
import json
import os
import tomllib
from dataclasses import asdict, dataclass, fields
from pathlib import Path

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


def read_config(path: Path) -> ClientConfig | None:
    if not path.exists():
        return None
    with path.open("rb") as file:
        data = tomllib.load(file)
    known = {field.name for field in fields(ClientConfig)}
    return ClientConfig(**{key: value for key, value in data.items() if key in known})


def write_config(path: Path, config: ClientConfig) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = "".join(f"{key} = {_toml_value(value)}\n" for key, value in asdict(config).items())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(lines.encode())
    path.chmod(0o600)


def _toml_value(value: str | int | float | bool) -> str:
    return TOML_STRING.encode(value).translate(TOML_ESCAPES)
