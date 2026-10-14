from collections.abc import Mapping
from importlib.metadata import entry_points
from typing import Any

from wildburrow import config

KINDS = {
    "transport": ("wildburrow.transports", f"{config.PREFIX}{{}}_"),
    "auth": ("wildburrow.auth", f"{config.PREFIX}AUTH_{{}}_"),
    "dns": ("wildburrow.dns", f"{config.PREFIX}DNS_{{}}_"),
}


def available(kind: str) -> dict[str, Any]:
    group, _ = KINDS[kind]
    return {ep.name: ep for ep in entry_points(group=group)}


def load(kind: str, name: str, env: Mapping[str, str]) -> Any:
    found = available(kind)
    if name not in found:
        raise config.ConfigError(f"unknown {kind} plugin {name!r}; installed: {', '.join(sorted(found)) or 'none'}")
    cls = found[name].load()
    _, prefix = KINDS[kind]
    settings = config.load(cls.Settings, env, prefix.format(name.upper()))
    try:
        return cls(settings)
    except config.ConfigError as exc:
        raise config.ConfigError(f"{kind} plugin {name!r}: {exc}") from None
