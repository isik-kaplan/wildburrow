import re

UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
DURATION = re.compile(r"([1-9][0-9]*)([mhdw])")
EXAMPLES = "like 30m, 12h or 7d"


def seconds(raw: str) -> int | None:
    """How long `raw` (a count and one of the UNITS) lasts; None when it isn't one."""
    if not (match := DURATION.fullmatch(raw.strip().lower())):
        return None
    return int(match[1]) * UNITS[match[2]]
