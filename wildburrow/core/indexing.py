"""Whether search engines may index a tunnel: the server's rule, and a client's choice within it."""

from enum import Enum

from wildburrow.config import ConfigError


class Indexing(Enum):
    # No tunnel is indexed, whatever its client asks.
    NEVER = "never"
    # Tunnels stay out of search engines unless their client asks to be indexed.
    OPT_IN = "opt-in"
    # Tunnels are indexed unless their client asks not to be.
    OPT_OUT = "opt-out"


def parse(var: str, raw: str) -> Indexing:
    try:
        return Indexing(raw.strip().lower())
    except ValueError:
        expected = ", ".join(rule.value for rule in Indexing)
        raise ConfigError(f"{var}: expected one of {expected}, got {raw!r}") from None


def indexed(rule: Indexing, asked: bool | None) -> bool:
    """Whether a tunnel whose client asked `asked`, None for nothing, may be indexed under `rule`."""
    if rule is Indexing.NEVER:
        return False
    return rule is Indexing.OPT_OUT if asked is None else asked
