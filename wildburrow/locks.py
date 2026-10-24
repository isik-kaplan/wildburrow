"""What a locked tunnel is made of, shared by the client that asks for one and the server that keeps it."""

import dataclasses
import re
import secrets
from collections.abc import Callable, Iterable
from typing import Any

from wildburrow import durations
from wildburrow.config import PREFIX, SHOWN

LOCK_PREFIX = f"{PREFIX}LOCK_"
# Who logged in, as the app is told: a username or a link's label.
LABEL = re.compile(r"[A-Za-z0-9._@-]{1,64}")
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
PATH = re.compile(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)+")
# Headers a lock can't take over, since every request needs them as the visitor sent them.
RESERVED_HEADERS = frozenset(
    ["host", "cookie", "content-length", "content-type", "transfer-encoding", "connection", "upgrade", "te", "trailer"]
)
SECRET_BYTES = 32
KEY_BYTES = 32
PASSWORD_BYTES = 12
GUEST = "guest"
LINK = "link"
PASSWORD = "password"  # noqa: S105
# The most a client may send for one page.
MAX_PAGE_BYTES = 65536


@dataclasses.dataclass(frozen=True, slots=True)
class LockSettings:
    """How a locked tunnel looks to visitors, defaulted by the server and changed per tunnel by the client."""

    path: str = "/_wildburrow/login"
    cookie: str = "wildburrow"
    header: str = "X-Wildburrow-Auth"
    user_header: str = "X-Wildburrow-User"
    expires: str = dataclasses.field(default="", metadata={SHOWN: "when the browser closes"})
    confirm_links: bool = True
    page: str = dataclasses.field(default="", metadata={SHOWN: "built in"})
    link_page: str = dataclasses.field(default="", metadata={SHOWN: "built in"})
    message_page: str = dataclasses.field(default="", metadata={SHOWN: "built in"})

    def lifetime(self) -> int | None:
        """Seconds a login lasts; None for until the browser closes."""
        return durations.seconds(self.expires)


@dataclasses.dataclass(frozen=True, slots=True)
class ServerLockSettings(LockSettings):
    """The server's defaults for every lock, and what only the server decides."""

    attempts: int = 10
    code_expires: str = "10m"


DEFAULTS = LockSettings()
FIELDS = {field.name: field for field in dataclasses.fields(LockSettings)}
PAGES = ("page", "link_page", "message_page")


def problems(settings: LockSettings, named: Callable[[str], str]) -> list[str]:
    """What is wrong with `settings`, each problem led by the setting's name as `named` gives it."""
    found = []
    if not PATH.fullmatch(settings.path):
        found.append(f"{named('path')}: expected a path like {DEFAULTS.path}, got {settings.path!r}")
    if not TOKEN.fullmatch(settings.cookie):
        found.append(f"{named('cookie')}: {settings.cookie!r} can't be a cookie name")
    for field in ("header", "user_header"):
        value = getattr(settings, field)
        if not TOKEN.fullmatch(value) or value.lower() in RESERVED_HEADERS:
            found.append(f"{named(field)}: {value!r} can't be a header of its own")
    if settings.header.lower() == settings.user_header.lower():
        found.append(f"{named('header')} and {named('user_header')} must differ")
    if settings.expires and durations.seconds(settings.expires) is None:
        expected = f"expected a duration {durations.EXAMPLES}, or empty"
        found.append(f"{named('expires')}: {expected}, got {settings.expires!r}")
    for page in PAGES:
        if len(getattr(settings, page).encode()) > MAX_PAGE_BYTES:
            found.append(f"{named(page)}: larger than {MAX_PAGE_BYTES} bytes")
    return found


def random_key() -> str:
    """32 random bytes, URL-safe."""
    # token_urlsafe(None) asks for the default of 32 bytes, so that mutant is the same program.
    return secrets.token_urlsafe(KEY_BYTES)  # pragma: no mutate


def next_links(taken: Iterable[str], count: int) -> list[str]:
    """Labels for `count` more links, numbered on from the highest link-N among `taken`."""
    numbers = [int(label[len(LINK) + 1 :]) for label in taken if re.fullmatch(f"{LINK}-[1-9][0-9]*", label)]
    start = max(numbers, default=0) + 1
    return [f"{LINK}-{number}" for number in range(start, start + count)]


def safe_path(path: str) -> bool:
    """Whether a redirect to `path` stays on the host it's sent from: no other host, and nothing that ends a header."""
    printable = path.isascii() and path.isprintable() and " " not in path
    return printable and path.startswith("/") and not path.startswith("//") and "\\" not in path


def merged(defaults: LockSettings, overrides: Any) -> LockSettings:
    """`defaults` with the client's `overrides`, refusing anything that isn't a setting of the right type."""
    if not isinstance(overrides, dict):
        raise ValueError("lock settings must be an object")
    for name, value in overrides.items():
        field = FIELDS.get(name)
        if field is None:
            raise ValueError(f"{name!r} isn't a lock setting")
        if type(value) is not type(field.default):
            raise ValueError(f"lock setting {name!r} has the wrong type")
    return dataclasses.replace(defaults, **overrides)
