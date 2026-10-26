"""What a locked tunnel answers before anything reaches its client: the login page, invite links, and the hand-off
that carries one login to every host of the tunnel."""

import asyncio
import string
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from html import escape
from http import HTTPStatus
from importlib import resources
from urllib.parse import parse_qs, urlencode

from wildburrow import locks, protocol
from wildburrow.core.context import ServerContext
from wildburrow.core.locks import LINK_PATH, Entry, Lock, challenge, digest
from wildburrow.core.names import host_labels
from wildburrow.edge.messages import Request, response

FORM_BYTES = 8192
FORM_FIELDS = 8
# How many times a host sends a visitor to the home and back before saying their browser keeps no cookies.
# Why a login failed, as recorded.
LIMITED = "limited"
WRONG_PASSWORD = "wrong-password"  # noqa: S105
MAX_TRIES = 3
CHALLENGE_LENGTH = len(challenge(""))
VOUCH = "/vouch"
CLAIM = "/claim"
# What the login page carries through a login, to send the visitor on to where they were going.
HANDOFF = ("host", "to", "challenge")
CREDENTIALS = ("username", "password")
SAFE = frozenset({"GET", "HEAD"})
POST = "POST"
HTML = "text/html; charset=utf-8"
# The built-in pages load nothing; one of the operator's or client's own may, but no page can be framed.
STRICT = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
FRAMES = "frame-ancestors 'none'"
PRIVATE = [("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"), ("X-Content-Type-Options", "nosniff")]
PAGES = {"page": "login", "link_page": "link", "message_page": "message"}
BUILT_IN = {page: (resources.files(__package__) / "pages" / f"{name}.html").read_text() for page, name in PAGES.items()}
NOT_SHARED = ("This page is private", "Ask whoever shared it for an invite link.")
SPENT = ("This link can't be used", "It was already used, or it has ended. Ask whoever shared it for a new one.")
IN = ("You're in", "Open any address of this tunnel.")
STUCK = (
    "Couldn't log you in here",
    "Your browser didn't keep the cookie logging in needs. Allow cookies for this site, then reload.",
)
WRONG = "Wrong username or password."
SLOW = "Too many tries. Wait a minute, then try again."


# Reads that many bytes of the request's body, in the time the edge allows.
type Body = Callable[[int], Awaitable[bytes]]


@dataclass(frozen=True, slots=True)
class Admitted:
    """A request let through, with the head to forward in place of the one the visitor sent, and who it's from."""

    head: bytes
    entry: Entry


def _page(lock: Lock, which: str, status: HTTPStatus, cookies: list[str], **values: str) -> bytes:
    """One of the lock's pages, `values` already escaped; the operator's or client's own replaces the built-in."""
    own = getattr(lock.settings, which)
    page = string.Template(own or BUILT_IN[which]).safe_substitute(values).encode()
    headers = [("Content-Security-Policy", FRAMES if own else STRICT), *PRIVATE, *_set(cookies)]
    return response(status, headers, page, HTML)


def _message(lock: Lock, status: HTTPStatus, text: tuple[str, str], cookies: list[str] | None = None) -> bytes:
    heading, message = map(escape, text)
    return _page(lock, "message_page", status, cookies or [], heading=heading, message=message)


def _plain(status: HTTPStatus, text: str) -> bytes:
    return response(status, PRIVATE, f"{text}\n".encode())


def _set(cookies: list[str]) -> list[tuple[str, str]]:
    return [("Set-Cookie", cookie) for cookie in cookies]


def _redirect(location: str, cookies: list[str]) -> bytes:
    return response(HTTPStatus.SEE_OTHER, [("Location", location), *PRIVATE, *_set(cookies)])


def _cookie(lock: Lock, name: str, value: str, max_age: int | None) -> str:
    cookie = f"{name}={value}; Path=/; HttpOnly; SameSite=Lax"
    if lock.secure:
        cookie += "; Secure"
    return cookie if max_age is None else f"{cookie}; Max-Age={max_age}"


def _login_cookie(lock: Lock, name: str, host: str, entry: Entry, until: int) -> str:
    max_age = None if until == 0 else max(until - lock.now(), 0)
    return _cookie(lock, name, lock.cookie(host, entry, until), max_age)


def _home_cookie(lock: Lock, entry: Entry, until: int) -> str:
    return _login_cookie(lock, lock.home_cookie_name(), lock.home, entry, until)


def _params(query: str) -> dict[str, str]:
    try:
        parsed = parse_qs(query, max_num_fields=FORM_FIELDS)
    except ValueError:
        return {}
    return {key: values[0] for key, values in parsed.items()}


def _back(fields: dict[str, str]) -> str:
    """Where to send a visitor on to: the path they were going to, when it stays on this host."""
    to = fields.get("to")
    return to if to is not None and locks.safe_path(to) else "/"


async def _form(request: Request, body: Body) -> dict[str, str] | bytes:
    """The fields of a posted form, or the response refusing it."""
    length = request.header("content-length") or "0"
    if request.header("transfer-encoding") is not None:
        return response(HTTPStatus.LENGTH_REQUIRED)
    if not length.isdigit():
        return response(HTTPStatus.BAD_REQUEST)
    if int(length) > FORM_BYTES:
        return response(HTTPStatus.CONTENT_TOO_LARGE)
    try:
        data = await body(int(length))
    except asyncio.IncompleteReadError, TimeoutError:
        return response(HTTPStatus.BAD_REQUEST)
    return _params(data.decode()) if data.isascii() else response(HTTPStatus.BAD_REQUEST)


def serves(ctx: ServerContext, lock: Lock, host: str) -> bool:
    """Whether `host` is one of the tunnel's own, the only kind a login is handed to."""
    labels = host_labels(host, ctx.domain)
    tunnel = None if labels is None else ctx.registry.resolve(labels)
    return tunnel is not None and tunnel.lock is not None and tunnel.lock.id == lock.id


def _handoff(ctx: ServerContext, lock: Lock, fields: dict[str, str]) -> tuple[str, str, str] | None:
    """The host, path and challenge of a login to hand on, when the fields carry a sound one."""
    if not all(key in fields for key in HANDOFF):
        return None
    host, to, asked = (fields[key] for key in HANDOFF)
    if host == lock.home or not serves(ctx, lock, host):
        return None
    if not locks.safe_path(to) or len(asked) != CHALLENGE_LENGTH:
        return None
    return host, to, asked


def _going(ctx: ServerContext, lock: Lock, fields: dict[str, str]) -> str:
    """The host a visitor logging in at the home is going to."""
    handoff = _handoff(ctx, lock, fields)
    return lock.home if handoff is None else handoff[0]


def _login(lock: Lock, status: HTTPStatus, fields: dict[str, str], title: str, error: str = "") -> bytes:
    """The login page for a visitor going to `title`, carrying `fields` on through the login."""
    if not lock.has_passwords():
        return _message(lock, HTTPStatus.UNAUTHORIZED, NOT_SHARED)
    carried = {key: fields[key] for key in HANDOFF if key in fields}
    hidden = "".join(
        f'<input type="hidden" name="{escape(key)}" value="{escape(value)}">' for key, value in carried.items()
    )
    return _page(
        lock, "page", status, [], title=escape(title), action=escape(lock.prefix), hidden=hidden, error=escape(error)
    )


def _arrived(lock: Lock, path: str, cookies: list[str]) -> bytes:
    """A visitor logged in at the home and going nowhere else: on to `path`, or told they're in on the domain."""
    if lock.on_domain:
        return _message(lock, HTTPStatus.OK, IN, cookies)
    return _redirect(path, cookies)


def _onward(
    ctx: ServerContext, lock: Lock, entry: Entry, until: int, fields: dict[str, str], cookies: list[str]
) -> bytes:
    """Where a visitor logged in at the home goes next: back to the host that sent them, with a code, or on at home."""
    if (handoff := _handoff(ctx, lock, fields)) is None:
        return _arrived(lock, _back(fields), cookies)
    host, to, asked = handoff
    code = lock.issue(host, asked, entry, until, to)
    ctx.record.handoff(lock, entry, digest(code), host)
    claim = f"{lock.scheme}://{host}{lock.settings.path}{CLAIM}?{urlencode({'code': code, 'to': to})}"
    return _redirect(claim, cookies)


def _landing(ctx: ServerContext, lock: Lock, entry: Entry, cookies: list[str]) -> bytes:
    """Where an opened link takes the visitor: its host and path, or the home."""
    if entry.host and entry.host != lock.home and serves(ctx, lock, entry.host):
        return _redirect(f"{lock.scheme}://{entry.host}{entry.path}", cookies)
    return _arrived(lock, entry.path, cookies)


def _at_home(lock: Lock, request: Request) -> tuple[Entry, int] | None:
    return lock.admitted(lock.home, request.cookies().get(lock.home_cookie_name()))


def _link(ctx: ServerContext, lock: Lock, request: Request, key: str) -> bytes:
    entry = lock.link(key)
    if entry is None:
        if _at_home(lock, request) is not None:
            return _arrived(lock, "/", [])
        return _message(lock, HTTPStatus.GONE, SPENT)
    if request.method == POST or (request.method == "GET" and not lock.settings.confirm_links):
        lock.spend(entry)
        ctx.record.link_opened(lock, entry, request.peer, request, used=True)
        ctx.record.login_attempt(lock, "link", entry.label, entry, request.peer, request, None)
        return _landing(ctx, lock, entry, [_home_cookie(lock, entry, lock.until())])
    if request.method in SAFE:
        ctx.record.link_opened(lock, entry, request.peer, request, used=False)
        title = entry.host or lock.home
        return _page(lock, "link_page", HTTPStatus.OK, [], title=escape(title), action=escape(request.path()))
    return response(HTTPStatus.METHOD_NOT_ALLOWED)


async def _home(ctx: ServerContext, lock: Lock, request: Request, rest: str, body: Body) -> bytes:
    """The lock's own pages on its home: logging in, links, and vouching for a visitor to another host."""
    if rest.startswith(LINK_PATH):
        return _link(ctx, lock, request, rest.removeprefix(LINK_PATH))
    if rest not in ("", VOUCH):
        return response(HTTPStatus.NOT_FOUND)
    if request.method == POST and rest == "":
        fields = await _form(request, body)
        if isinstance(fields, bytes):
            return fields
        username = fields.get(CREDENTIALS[0], "")
        if lock.limited():
            ctx.record.login_attempt(lock, "form", username, None, request.peer, request, LIMITED)
            return _login(lock, HTTPStatus.TOO_MANY_REQUESTS, fields, _going(ctx, lock, fields), SLOW)
        if (entry := lock.login(*(fields.get(key, "") for key in CREDENTIALS))) is None:
            ctx.record.login_attempt(lock, "form", username, None, request.peer, request, WRONG_PASSWORD)
            return _login(lock, HTTPStatus.UNAUTHORIZED, fields, _going(ctx, lock, fields), WRONG)
        ctx.record.login_attempt(lock, "form", username, entry, request.peer, request, None)
        lock.logged_in(entry)
        until = lock.until()
        return _onward(ctx, lock, entry, until, fields, [_home_cookie(lock, entry, until)])
    if request.method not in SAFE:
        return response(HTTPStatus.METHOD_NOT_ALLOWED)
    fields = _params(request.query())
    if (found := _at_home(lock, request)) is not None:
        return _onward(ctx, lock, *found, fields, [])
    return _login(lock, HTTPStatus.UNAUTHORIZED, fields, _going(ctx, lock, fields))


def _pending(lock: Lock, request: Request) -> tuple[int, str]:
    """How often this browser has been sent to the home for a login here, and the verifier it keeps for it."""
    value = request.cookies().get(lock.pending_name())
    if value is None:
        return 0, ""
    tries, _, verifier = value.partition(".")
    return int(tries) if tries.isdigit() else 0, verifier


def _claim(ctx: ServerContext, lock: Lock, request: Request) -> bytes:
    """A host taking the code the home sent the visitor back with, from the browser it was made for."""
    if request.method not in SAFE:
        return response(HTTPStatus.METHOD_NOT_ALLOWED)
    fields = _params(request.query())
    _, verifier = _pending(lock, request)
    code = fields.get("code")
    redeemed = None if code is None or not verifier else lock.redeem(code, request.host, verifier)
    if redeemed is None:
        # Back to the page, which sends the visitor round again, counting the tries.
        return _redirect(_back(fields), [])
    found, entry = redeemed
    ctx.record.redeemed(digest(str(code)))
    lock.seen(entry)
    kept = _login_cookie(lock, lock.cookie_name(), request.host, entry, found.until)
    return _redirect(found.to, [kept, _cookie(lock, lock.pending_name(), "", 0)])


def _bounce(lock: Lock, request: Request) -> bytes:
    """Sends a visitor with no login on this host to the home, keeping a verifier only this browser holds."""
    tried, _ = _pending(lock, request)
    if tried >= MAX_TRIES:
        return _message(lock, HTTPStatus.FORBIDDEN, STUCK, [_cookie(lock, lock.pending_name(), "", 0)])
    verifier = locks.random_key()
    query = urlencode({"host": request.host, "to": request.target, "challenge": challenge(verifier)})
    kept = _cookie(lock, lock.pending_name(), f"{tried + 1}.{verifier}", lock.code_seconds)
    return _redirect(f"{lock.scheme}://{lock.home}{lock.prefix}{VOUCH}?{query}", [kept])


def _admit(lock: Lock, request: Request, entry: Entry) -> Admitted:
    """`request` with the lock's own cookies and header taken out, and the app told who logged in."""
    lock.seen(entry)
    ours = {lock.cookie_name(), lock.pending_name()}
    dropped = {lock.settings.header.lower(), lock.settings.user_header.lower()}
    headers = []
    for key, value in request.headers:
        if key.lower() in dropped:
            continue
        if key.lower() == "cookie":
            pairs = [pair.strip() for pair in value.split(";")]
            kept = [pair for pair in pairs if pair and pair.partition("=")[0] not in ours]
            if not kept:
                continue
            value = "; ".join(kept)
        headers.append((key, value))
    headers.append((lock.settings.user_header, entry.label))
    return Admitted(request.head(headers), entry)


async def guard(ctx: ServerContext, lock: Lock, request: Request, body: Body) -> bytes | Admitted:
    """What a request to a locked tunnel gets: let through when it carries a login, else the way to log in."""
    path, base = request.path(), lock.settings.path
    if path == base or path.startswith(base + "/"):
        rest = path.removeprefix(base)
        if request.host == lock.home:
            return await _home(ctx, lock, request, rest, body)
        return _claim(ctx, lock, request) if rest == CLAIM else response(HTTPStatus.NOT_FOUND)
    if (given := request.header(lock.settings.header.lower())) is not None:
        username, _, password = given.partition(":")
        if lock.limited():
            ctx.record.login_attempt(lock, "header", username, None, request.peer, request, LIMITED)
            return _plain(HTTPStatus.TOO_MANY_REQUESTS, SLOW)
        if (entry := lock.login(username, password)) is None:
            ctx.record.login_attempt(lock, "header", username, None, request.peer, request, WRONG_PASSWORD)
            return _plain(HTTPStatus.UNAUTHORIZED, f"{lock.settings.header}: {WRONG}")
        ctx.record.login_attempt(lock, "header", username, entry, request.peer, request, None)
        return _admit(lock, request, entry)
    if (found := lock.admitted(request.host, request.cookies().get(lock.cookie_name()))) is not None:
        return _admit(lock, request, found[0])
    if request.method not in SAFE:
        return _plain(HTTPStatus.UNAUTHORIZED, "This address needs a login.")
    if request.host == lock.home:
        return _login(lock, HTTPStatus.UNAUTHORIZED, {"to": request.target}, lock.home)
    return _bounce(lock, request)


async def home(ctx: ServerContext, request: Request, body: Body) -> bytes:
    """The server's own domain, as the home of locks on tunnels with only wildcard names."""
    lock_id, sep, rest = request.path().removeprefix(protocol.LOCK_PATH).partition("/")
    lock = ctx.locks.get(lock_id)
    if lock is None or not lock.on_domain:
        return response(HTTPStatus.NOT_FOUND)
    return await _home(ctx, lock, request, f"/{rest}" if sep else "", body)
