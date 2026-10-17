"""`KEY="value"` lines, in the subset of systemd's EnvironmentFile syntax that it and `serve --env-file` both read."""

import os
from collections.abc import Mapping
from pathlib import Path

# The characters systemd unescapes inside double quotes.
ESCAPED = '\\"$`'


class EnvFileError(Exception):
    pass


def fits(value: str) -> bool:
    # Anything str.splitlines splits on would end the line when read back, not just a newline.
    return len(f"[{value}]".splitlines()) == 1


def quote(value: str) -> str:
    if not fits(value):
        raise ValueError("an environment file value can't span lines")
    return '"' + "".join("\\" + char if char in ESCAPED else char for char in value) + '"'


def _unquote(raw: str) -> str:
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return raw
    chars, escaped = [], False
    for char in raw[1:-1]:
        if escaped or char != "\\":
            chars.append(char)
        escaped = not escaped and char == "\\"
    return "".join(chars)


def parse(text: str) -> dict[str, str]:
    values = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not (line := line.strip()) or line.startswith("#"):
            continue
        key, sep, raw = line.partition("=")
        if not sep or not key.strip():
            raise EnvFileError(f"line {number}: expected KEY=VALUE")
        values[key.strip()] = _unquote(raw.strip())
    return values


def read(path: Path) -> dict[str, str]:
    try:
        return parse(path.read_text())
    except OSError as exc:
        raise EnvFileError(str(exc)) from None
    except EnvFileError as exc:
        raise EnvFileError(f"{path}: {exc}") from None


def write(path: Path, values: Mapping[str, str], mode: int) -> None:
    text = "".join(f"{key}={quote(value)}\n" for key, value in values.items())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as file:
        file.write(text)
    path.chmod(mode)
