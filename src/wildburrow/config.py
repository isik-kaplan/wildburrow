import dataclasses
from collections.abc import Mapping
from pathlib import Path
from typing import Any, get_type_hints

PREFIX = "WILDBURROW_"
TRUE = {"1", "true", "yes", "on"}
FALSE = {"0", "false", "no", "off"}


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


def load[T](cls: type[T], env: Mapping[str, str], prefix: str) -> T:
    hints = get_type_hints(cls)
    values: dict[str, Any] = {}
    missing = []
    for field in dataclasses.fields(cls):  # type: ignore[arg-type]
        var = f"{prefix}{field.name.upper()}"
        if var in env:
            values[field.name] = _convert(var, env[var], hints[field.name])
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
    data_dir: Path = Path("/data")
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
