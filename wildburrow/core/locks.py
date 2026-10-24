"""A locked tunnel's logins, kept in memory with the tunnel: who may get in, and the cookies and codes that say so."""

import base64
import binascii
import hashlib
import hmac
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from wildburrow import locks, protocol
from wildburrow.locks import LINK, PASSWORD, LockSettings

ATTEMPT_WINDOW = 60
MAX_CODES = 1000
ID_LENGTH = 16
DIGEST = re.compile(r"[0-9a-f]{64}")
HOST_PREFIX = "__Host-"
PENDING = "-pending"
LINK_PATH = "/link/"


def _b64(data: bytes) -> str:
    # Only digests come here, whose last character is never an X, so stripping one too is the same program.
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()  # pragma: no mutate


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def challenge(verifier: str) -> str:
    """What a host hands the home in place of the verifier it keeps in the visitor's browser."""
    return _b64(hashlib.sha256(verifier.encode()).digest())


@dataclass(frozen=True, slots=True)
class Locking:
    """The server's side of every lock: defaults for what a client leaves out, and what only the server decides."""

    settings: LockSettings = locks.DEFAULTS
    attempts: int = 10
    code_seconds: int = 600


@dataclass(slots=True)
class Entry:
    label: str
    kind: str
    # The password's HMAC under the lock's secret.
    password: bytes = field(default=b"", repr=False)
    # The link key's digest, and where the link lands: a host of the tunnel, "" for the home, and a path.
    key: str = ""
    host: str = ""
    path: str = "/"
    expires: int | None = None
    used: int | None = None
    ended: bool = False
    logins: int = 0
    seen: int | None = None


@dataclass(frozen=True, slots=True)
class Code:
    host: str
    challenge: str
    label: str
    # When the login it carries ends, 0 for when the browser closes.
    until: int
    to: str
    made: float


class Lock:
    def __init__(
        self,
        secret: bytes,
        settings: LockSettings,
        home: str,
        on_domain: bool,
        secure: bool,
        locking: Locking,
        changed: Callable[[dict[str, Any]], None],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.secure = secure
        self.scheme = "https" if secure else "http"
        self.code_seconds = locking.code_seconds
        self.id = hmac.new(secret, b"id", hashlib.sha256).hexdigest()[:ID_LENGTH]
        # The host every login happens on, and where under it; a tunnel with only wildcard names has the server's own
        # domain, where each lock homed there has a path and a cookie of its own.
        self.home = home
        self.on_domain = on_domain
        self.prefix = f"{protocol.LOCK_PATH}{self.id}" if on_domain else settings.path
        self.entries: dict[str, Entry] = {}
        self._secret = secret
        self._locking = locking
        self._changed = changed
        self._clock = clock
        self._failures: deque[float] = deque()
        self._codes: dict[str, Code] = {}

    def _mac(self, *parts: str) -> bytes:
        return hmac.new(self._secret, "\0".join(parts).encode(), hashlib.sha256).digest()

    def now(self) -> int:
        return int(self._clock())

    def cookie_name(self) -> str:
        """The login cookie on the tunnel's own hosts."""
        return (HOST_PREFIX if self.secure else "") + self.settings.cookie

    def home_cookie_name(self) -> str:
        """The login cookie on the home: the server's domain keeps one for each lock homed there."""
        return f"{self.cookie_name()}-{self.id}" if self.on_domain else self.cookie_name()

    def pending_name(self) -> str:
        """The cookie keeping a hand-off's verifier while the visitor is away at the home."""
        return self.cookie_name() + PENDING

    def add_password(self, label: str, password: str) -> None:
        self.entries[label] = Entry(label, PASSWORD, password=self._mac(PASSWORD, password))

    def add_link(self, label: str, key: str, host: str, path: str, expires: int | None, used: int | None) -> None:
        self.entries[label] = Entry(label, LINK, key=key, host=host, path=path, expires=expires, used=used)

    def new_link(self, label: str, host: str, path: str, expires: int | None) -> str:
        """A new link's key, which only its URL carries; the lock keeps its digest."""
        key = locks.random_key()
        self.add_link(label, digest(key), host, path, expires, None)
        return key

    def mint(self, label: str, host: str, path: str, expires: int | None) -> str:
        """A new link, told to the client so it outlives a reconnect."""
        key = self.new_link(label, host, path, expires)
        self._changed(self.state())
        return key

    def link_url(self, key: str) -> str:
        return f"{self.scheme}://{self.home}{self.prefix}{LINK_PATH}{key}"

    def has_passwords(self) -> bool:
        return any(entry.kind == PASSWORD and not entry.ended for entry in self.entries.values())

    def _live(self, label: str) -> Entry | None:
        entry = self.entries.get(label)
        return None if entry is None or entry.ended else entry

    def limited(self) -> bool:
        cutoff = self._clock() - ATTEMPT_WINDOW
        while self._failures and self._failures[0] <= cutoff:
            self._failures.popleft()
        return len(self._failures) >= self._locking.attempts

    def login(self, username: str, password: str) -> Entry | None:
        """The password entry these open, counting a failure against the lock."""
        entry = self._live(username)
        given = self._mac(PASSWORD, password)
        if entry is not None and entry.kind == PASSWORD and hmac.compare_digest(entry.password, given):
            return entry
        self._failures.append(self._clock())
        return None

    def until(self) -> int:
        """When a login made now ends, 0 for when the browser closes."""
        lifetime = self.settings.lifetime()
        return 0 if lifetime is None else int(self._clock()) + lifetime

    def cookie(self, host: str, entry: Entry, until: int) -> str:
        mac = _b64(self._mac("cookie", host, entry.label, str(until)))
        return f"{entry.label}.{until}.{mac}"

    def admitted(self, host: str, value: str | None) -> tuple[Entry, int] | None:
        """Whom a cookie for `host` lets in, and until when."""
        if value is None or value.count(".") < 2:
            return None
        label, until, mac = value.rsplit(".", 2)
        if not until.isdigit() or not hmac.compare_digest(mac, _b64(self._mac("cookie", host, label, until))):
            return None
        if (entry := self._live(label)) is None or (int(until) and int(until) <= self._clock()):
            return None
        return entry, int(until)

    def link(self, key: str) -> Entry | None:
        """The link `key` opens, while it can still be used."""
        found = digest(key)
        for entry in self.entries.values():
            if entry.kind == LINK and hmac.compare_digest(entry.key, found):
                usable = not entry.ended and entry.used is None
                fresh = entry.expires is None or entry.expires > self._clock()
                return entry if usable and fresh else None
        return None

    def spend(self, entry: Entry) -> None:
        entry.used = int(self._clock())
        self.logged_in(entry)
        self._changed(self.state())

    def logged_in(self, entry: Entry) -> None:
        entry.logins += 1
        self.seen(entry)

    def seen(self, entry: Entry) -> None:
        entry.seen = int(self._clock())

    def end(self, label: str) -> bool:
        if (entry := self._live(label)) is None:
            return False
        entry.ended = True
        self._changed(self.state())
        return True

    def issue(self, host: str, verifier_challenge: str, entry: Entry, until: int, to: str) -> str:
        """A one-time code that logs the browser holding the verifier in on `host`."""
        self._expire_codes()
        while len(self._codes) >= MAX_CODES:
            del self._codes[next(iter(self._codes))]
        code = locks.random_key()
        self._codes[digest(code)] = Code(host, verifier_challenge, entry.label, until, to, self._clock())
        return code

    def redeem(self, code: str, host: str, verifier: str) -> tuple[Code, Entry] | None:
        """What `code` carries, used up, when `host` is the one it was made for and the browser holds its verifier."""
        self._expire_codes()
        found = self._codes.pop(digest(code), None)
        if found is None or found.host != host or not hmac.compare_digest(found.challenge, challenge(verifier)):
            return None
        if (entry := self._live(found.label)) is None:
            return None
        return found, entry

    def _expire_codes(self) -> None:
        cutoff = self._clock() - self.code_seconds
        for key, code in list(self._codes.items()):
            if code.made <= cutoff:
                del self._codes[key]

    def state(self) -> dict[str, Any]:
        """What the client keeps and sends back on reconnecting, so links and their use outlive a dropped connection."""
        links = {
            entry.label: {
                "key": entry.key,
                "host": entry.host,
                "path": entry.path,
                "expires": entry.expires,
                "used": entry.used,
            }
            for entry in self.entries.values()
            if entry.kind == LINK
        }
        return {"links": links, "ended": [entry.label for entry in self.entries.values() if entry.ended]}

    def listing(self) -> list[dict[str, Any]]:
        return [
            {
                "who": entry.label,
                "kind": entry.kind,
                "used": entry.used,
                "logins": entry.logins,
                "seen": entry.seen,
                "expires": entry.expires,
                "ended": entry.ended,
            }
            for entry in self.entries.values()
        ]


def _typed(value: Any, kind: type, what: str) -> Any:
    if type(value) is not kind:
        raise ValueError(f"{what} has the wrong type")
    return value


def _label(value: Any, taken: set[str]) -> str:
    label = _typed(value, str, "a lock label")
    if not locks.LABEL.fullmatch(label):
        raise ValueError(f"{label!r} can't name a login: use 1-64 letters, digits and . _ @ -")
    if label in taken:
        raise ValueError(f"{label!r} names two logins")
    taken.add(label)
    return label


def _optional_int(value: Any, what: str) -> int | None:
    return None if value is None else _typed(value, int, what)


def build(
    spec: Any,
    home: str,
    on_domain: bool,
    secure: bool,
    locking: Locking,
    changed: Callable[[dict[str, Any]], None],
    clock: Callable[[], float] = time.time,
) -> tuple[Lock, list[tuple[str, str]]]:
    """The lock a client asks for, and the links it asked to have minted, by label and key."""
    spec = _typed(spec, dict, "a lock")
    text = _typed(spec.get("secret"), str, "the lock's secret")
    try:
        secret = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except binascii.Error:
        raise ValueError("the lock's secret isn't base64") from None
    if len(secret) < locks.SECRET_BYTES:
        raise ValueError("the lock's secret is too short")
    settings = locks.merged(locking.settings, spec.get("settings", {}))
    if found := locks.problems(settings, lambda name: f"lock setting {name!r}"):
        raise ValueError("; ".join(found))
    lock = Lock(secret, settings, home, on_domain, secure, locking, changed, clock)
    taken: set[str] = set()
    for username, password in _typed(spec.get("users", {}), dict, "the lock's users").items():
        lock.add_password(_label(username, taken), _typed(password, str, "a password"))
    for label, link in _typed(spec.get("links", {}), dict, "the lock's links").items():
        link = _typed(link, dict, "a link")
        key = _typed(link.get("key"), str, "a link's key")
        if not DIGEST.fullmatch(key):
            raise ValueError("a link's key must be its digest")
        host = _typed(link.get("host", ""), str, "a link's host")
        path = _typed(link.get("path", "/"), str, "a link's path")
        if not locks.safe_path(path):
            raise ValueError(f"{path!r} isn't a path a link can land on")
        expires = _optional_int(link.get("expires"), "a link's expiry")
        lock.add_link(_label(label, taken), key, host, path, expires, _optional_int(link.get("used"), "a link's use"))
    for label in _typed(spec.get("ended", []), list, "the lock's ended logins"):
        if (entry := lock.entries.get(_typed(label, str, "an ended login"))) is not None:
            entry.ended = True
    minted = []
    for request in _typed(spec.get("mint", []), list, "the links to mint"):
        request = _typed(request, dict, "a link to mint")
        label = _label(request.get("label"), taken)
        minted.append((label, lock.new_link(label, "", "/", _optional_int(request.get("expires"), "a link's expiry"))))
    if not lock.entries:
        raise ValueError("a lock needs a password or a link")
    return lock, minted
