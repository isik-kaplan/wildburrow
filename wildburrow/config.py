import dataclasses
from collections.abc import Mapping
from pathlib import Path
from typing import Any, get_type_hints

PREFIX = "WILDBURROW_"
TRUE = {"1", "true", "yes", "on"}
FALSE = {"0", "false", "no", "off"}
FILE_SUFFIX = "_FILE"
# Field metadata naming the default to show where the real one is worked out later.
SHOWN = "shown"
# Field metadata marking a value to ask for without echoing it.
SECRET = "secret"  # noqa: S105


class ConfigError(Exception):
    pass


def _convert(var: str, raw: str, kind: Any) -> Any:
    if kind is bool:
        if raw.lower() in TRUE:
            return True
        if raw.lower() in FALSE:
            return False
        raise ConfigError(f"{var}: expected one of {sorted(TRUE | FALSE)}, got {raw!r}")
    if kind is int:
        try:
            return int(raw)
        except ValueError:
            raise ConfigError(f"{var}: expected an integer, got {raw!r}") from None
    if kind == tuple[str, ...]:
        return tuple(item.strip() for item in raw.split(",") if item.strip())
    return kind(raw)


def _read(var: str, env: Mapping[str, str]) -> str | None:
    path = env.get(var + FILE_SUFFIX)
    if path is None:
        return env.get(var)
    if var in env:
        raise ConfigError(f"set {var} or {var}{FILE_SUFFIX}, not both")
    try:
        return Path(path).read_text().strip()
    except OSError as exc:
        raise ConfigError(f"{var}{FILE_SUFFIX}: {exc}") from None


def load[T](cls: type[T], env: Mapping[str, str], prefix: str) -> T:
    hints = get_type_hints(cls)
    values: dict[str, Any] = {}
    missing = []
    for field in dataclasses.fields(cls):  # type: ignore[arg-type]
        var = f"{prefix}{field.name.upper()}"
        if (raw := _read(var, env)) is not None:
            values[field.name] = _convert(var, raw, hints[field.name])
        elif field.default is dataclasses.MISSING:
            missing.append(var)
    if missing:
        raise ConfigError(f"missing required setting(s): {', '.join(missing)}")
    return cls(**values)


@dataclasses.dataclass(frozen=True, slots=True)
class ServerSettings:
    domain: str
    transports: tuple[str, ...] = ("ssh",)
    auth: tuple[str, ...] = ("key",)
    client_transport: str = dataclasses.field(default="", metadata={SHOWN: "the first clients can log in over"})
    client_auth: str = dataclasses.field(default="", metadata={SHOWN: "its first method in AUTH"})
    admins: tuple[str, ...] = ("signers",)
    see: str = "own"
    kick: str = "own"
    data_dir: Path = Path("~/.local/state/wildburrow")
    http_host: str = "0.0.0.0"  # noqa: S104
    http_port: int = 80
    max_depth: int = 5
    max_header_bytes: int = 65536
    header_timeout: int = 30
    dns: str = ""
    dns_manage_records: bool = False
    https_host: str = "0.0.0.0"  # noqa: S104
    https_port: int = 443
    acme_directory: str = "https://acme-v02.api.letsencrypt.org/directory"
    acme_email: str = ""
    acme_propagation_seconds: int = 30
    acme_timeout_seconds: int = 300
    renew_before_days: int = 30
    renew_interval_seconds: int = 43200
    http_proxy_protocol: bool = False
    https_proxy_protocol: bool = False
    proxy_trusted: tuple[str, ...] = (
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "data_dir", self.data_dir.expanduser())
        except RuntimeError:
            raise ConfigError(f"{PREFIX}DATA_DIR is required when there is no home directory") from None
