import re
from dataclasses import dataclass

from wildburrow.core.errors import BindRejected

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MAX_FQDN_LENGTH = 253


class InvalidName(BindRejected):
    pass


@dataclass(frozen=True, slots=True)
class Name:
    labels: tuple[str, ...]
    wildcard: bool = False

    def __str__(self) -> str:
        return ".".join(("*", *self.labels) if self.wildcard else self.labels)

    def fqdn(self, domain: str) -> str:
        return f"{self}.{domain}"


def parse_name(raw: str, domain: str, max_depth: int) -> Name:
    if not raw.isascii():
        raise InvalidName(f"{raw!r}: must be ascii")
    parts = raw.lower().split(".")
    wildcard = parts[0] == "*"
    labels = tuple(parts[1:] if wildcard else parts)
    if not labels:
        raise InvalidName(f"{raw!r}: a wildcard needs at least one label after '*.'")
    if len(labels) + wildcard > max_depth:
        raise InvalidName(f"{raw!r}: deeper than the allowed {max_depth} labels")
    for label in labels:
        if label == "*":
            raise InvalidName(f"{raw!r}: '*' is only allowed as the leftmost label")
        if not LABEL.fullmatch(label):
            raise InvalidName(f"{raw!r}: {label!r} must be 1-63 of a-z, 0-9 and '-', not starting or ending with '-'")
    name = Name(labels, wildcard)
    if len(name.fqdn(domain)) > MAX_FQDN_LENGTH:
        raise InvalidName(f"{raw!r}: longer than {MAX_FQDN_LENGTH} characters with the domain")
    return name


ANY = "any"


def parse_patterns(raw: str) -> tuple[str, ...] | None:
    """The names a token may claim: `any`, or comma-separated names where a `*` label stands for any one label."""
    if raw.strip().lower() == ANY:
        return None
    patterns = tuple(dict.fromkeys(item.strip().lower() for item in raw.split(",") if item.strip()))
    if not patterns:
        raise InvalidName(f"no names given: pass the names it may claim, or {ANY}")
    for pattern in patterns:
        if not all(label == "*" or LABEL.fullmatch(label) for label in pattern.split(".")):
            raise InvalidName(f"{pattern!r}: labels are 1-63 of a-z, 0-9 and '-', or '*' for any one label")
    return patterns


def allows(patterns: tuple[str, ...] | None, name: Name) -> bool:
    if patterns is None:
        return True
    labels = str(name).split(".")
    return any(_matches(pattern.split("."), labels) for pattern in patterns)


def _matches(pattern: list[str], labels: list[str]) -> bool:
    return len(pattern) == len(labels) and all(pattern[i] in ("*", labels[i]) for i in range(len(labels)))


def host_labels(host: str, domain: str) -> tuple[str, ...] | None:
    host = host.lower()
    suffix = f".{domain}"
    if not host.endswith(suffix):
        return None
    labels = tuple(host[: -len(suffix)].split("."))
    if not all(LABEL.fullmatch(label) for label in labels):
        return None
    return labels
