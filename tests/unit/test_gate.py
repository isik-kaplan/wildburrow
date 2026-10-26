import asyncio
import hashlib
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from tests.unit.test_edge import exchange, running
from tests.unit.test_locks import NOW, SECRET_TEXT, Changes, Clock, bound, digest
from tests.unit.test_registry import FakeTunnel
from wildburrow.core.context import ServerContext
from wildburrow.core.locks import Lock, Locking, challenge, entry_id
from wildburrow.core.types import Identity
from wildburrow.edge import gate
from wildburrow.edge.gate import BUILT_IN, FORM_BYTES, FORM_FIELDS, MAX_TRIES, STRICT, Admitted
from wildburrow.edge.messages import parse_request
from wildburrow.locks import DEFAULTS, FIELDS, LINK, PASSWORD, LockSettings

ALICE = Identity("alice", "token", "alice")
HOME = "foo.example.com"
OTHER = "a.foo.example.com"
VERIFIER = "v" * 43


class Answer:
    def __init__(self, raw: bytes) -> None:
        head, _, self.body = raw.partition(b"\r\n\r\n")
        status, *lines = head.decode().split("\r\n")
        self.status = int(status.split(" ")[1])
        self.headers = [(key, value.strip()) for key, _, value in (line.partition(":") for line in lines)]

    def header(self, name: str) -> str | None:
        return next((value for key, value in self.headers if key == name), None)

    def cookies(self) -> list[str]:
        return [value for key, value in self.headers if key == "Set-Cookie"]


def locked(ctx: ServerContext, names: tuple[str, ...] = ("foo", "*.foo"), **changes: Any) -> Lock:
    """A lock on a tunnel holding `names`; `changes` that are lock settings go into its settings."""
    tunnel = FakeTunnel(ALICE)
    settings = {key: changes.pop(key) for key in list(changes) if key in FIELDS} | changes.pop("settings", {})
    raw = {"secret": SECRET_TEXT, "users": {"alice": "pw"}, "settings": settings} | changes
    ctx.lock(tunnel, list(names), raw, Changes())
    bound(ctx, tunnel, *names)
    assert tunnel.lock is not None
    return tunnel.lock


async def nothing(size: int) -> bytes:
    raise AssertionError("no body expected")


def request(method: str, host: str, target: str, *headers: str) -> Any:
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}", *headers]
    return parse_request(("\r\n".join(lines) + "\r\n\r\n").encode())


async def ask(
    ctx: ServerContext, lock: Lock, method: str, host: str, target: str, *headers: str, body: Any = nothing
) -> Answer:
    outcome = await gate.guard(ctx, lock, request(method, host, target, *headers), body)
    assert isinstance(outcome, bytes)
    return Answer(outcome)


def posted(form: dict[str, str]) -> tuple[str, Any]:
    data = urlencode(form).encode()

    async def body(size: int) -> bytes:
        assert size == len(data)
        return data

    return f"Content-Length: {len(data)}", body


def logged_in(lock: Lock, host: str, label: str = "alice", until: int = 0) -> str:
    name = lock.home_cookie_name() if host == lock.home else lock.cookie_name()
    [entry] = [entry for entry in lock.entries.values() if entry.label == label]
    return f"Cookie: {name}={lock.cookie(host, entry, until)}"


async def test_the_login_page_carries_a_hand_off_through(ctx: ServerContext) -> None:
    lock = locked(ctx, page="$title|$hidden")
    query = urlencode({"host": OTHER, "to": "/x", "challenge": challenge(VERIFIER), "other": "y"})
    page = await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/vouch?{query}")
    hidden = "".join(
        f'<input type="hidden" name="{key}" value="{value}">'
        for key, value in (("host", OTHER), ("to", "/x"), ("challenge", challenge(VERIFIER)))
    )
    assert page.body == f"{OTHER}|{hidden}".encode()


async def test_the_built_in_pages_load_nothing(ctx: ServerContext) -> None:
    lock = locked(ctx)
    page = await ask(ctx, lock, "GET", HOME, "/x")
    assert page.status == 401
    assert page.header("Content-Security-Policy") == STRICT
    assert page.header("Cache-Control") == "no-store"
    assert page.header("Referrer-Policy") == "no-referrer"
    assert page.header("X-Content-Type-Options") == "nosniff"
    assert page.header("Content-Type") == "text/html; charset=utf-8"
    assert set(re.findall(r"\$(\w+)", BUILT_IN["page"])) == {"title", "action", "error", "hidden"}
    assert set(re.findall(r"\$(\w+)", BUILT_IN["link_page"])) == {"title", "action"}
    assert set(re.findall(r"\$(\w+)", BUILT_IN["message_page"])) == {"heading", "message"}


async def test_the_login_page_escapes_what_it_carries(ctx: ServerContext) -> None:
    lock = locked(ctx, page="[$title|$action|$error|$hidden]")
    page = await ask(ctx, lock, "GET", HOME, '/"><x>')
    assert (
        page.body
        == f'[{HOME}|/_wildburrow/login||<input type="hidden" name="to" value="/&quot;&gt;&lt;x&gt;">]'.encode()
    )


async def test_a_wrong_password_says_so(ctx: ServerContext) -> None:
    lock = locked(ctx, page="$error")
    length, body = posted({"username": "alice", "password": "nope", "to": "/x", "extra": "dropped"})
    page = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
    assert (page.status, page.body) == (401, b"Wrong username or password.")


async def test_a_login_at_home_lands_where_the_visitor_was_going(ctx: ServerContext) -> None:
    lock = locked(ctx)
    for to, landing in [("/x?y=1", "/x?y=1"), ("//evil.org", "/"), ("", "/")]:
        length, body = posted({"username": "alice", "password": "pw", "to": to})
        landed = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
        assert (landed.status, landed.header("Location")) == (303, landing)
        [cookie] = landed.cookies()
        assert cookie.startswith("wildburrow=password:alice.0.")
        assert cookie.endswith("; Path=/; HttpOnly; SameSite=Lax")
    assert lock.entries[entry_id(PASSWORD, "alice")].logins == 3


async def test_a_login_lasts_as_long_as_the_lock_says(ctx: ServerContext) -> None:
    lock = locked(ctx, settings={"expires": "1h"})
    length, body = posted({"username": "alice", "password": "pw"})
    landed = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
    [cookie] = landed.cookies()
    assert cookie.endswith("; Max-Age=3600")


async def test_a_login_cookie_never_counts_down_past_zero() -> None:
    clock = Clock()
    lock = Lock(b"s" * 32, DEFAULTS, HOME, False, True, Locking(), Changes(), clock)
    lock.add_password("alice", "pw")
    cookie = gate._login_cookie(lock, lock.cookie_name(), HOME, lock.entries[entry_id(PASSWORD, "alice")], NOW - 5)
    assert cookie.startswith("__Host-wildburrow=password:alice.")
    assert cookie.endswith("; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0")
    alice = lock.entries[entry_id(PASSWORD, "alice")]
    assert gate._login_cookie(lock, "n", HOME, alice, NOW + 7).endswith("; Max-Age=7")


async def test_too_many_failures_stop_logins_for_a_while(ctx: ServerContext) -> None:
    ctx.locking = Locking(attempts=1)
    lock = locked(ctx, page="$error")
    length, body = posted({"username": "alice", "password": "nope"})
    await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
    length, body = posted({"username": "alice", "password": "pw"})
    page = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
    assert (page.status, page.body) == (429, b"Too many tries. Wait a minute, then try again.")
    assert lock.entries[entry_id(PASSWORD, "alice")].logins == 0


@pytest.mark.parametrize(
    ("headers", "body", "status"),
    [
        (("Transfer-Encoding: chunked",), nothing, 411),
        (("Content-Length: x",), nothing, 400),
        ((f"Content-Length: {FORM_BYTES + 1}",), nothing, 413),
    ],
)
async def test_forms_must_be_small_and_whole(
    ctx: ServerContext, headers: tuple[str, ...], body: Any, status: int
) -> None:
    lock = locked(ctx)
    assert (await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", *headers, body=body)).status == status


@pytest.mark.parametrize("failure", [asyncio.IncompleteReadError(b"", 5), TimeoutError()])
async def test_a_form_that_never_arrives_is_refused(ctx: ServerContext, failure: Exception) -> None:
    lock = locked(ctx)

    async def body(size: int) -> bytes:
        raise failure

    assert (await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", "Content-Length: 5", body=body)).status == 400


async def test_a_form_must_be_ascii(ctx: ServerContext) -> None:
    lock = locked(ctx)

    async def body(size: int) -> bytes:
        return "é".encode()

    assert (await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", "Content-Length: 2", body=body)).status == 400


async def test_a_form_at_the_limit_is_read(ctx: ServerContext) -> None:
    lock = locked(ctx, page="$error")
    data = b"username=alice&password=x&pad=" + b"x" * (FORM_BYTES - 30)
    assert len(data) == FORM_BYTES

    async def body(size: int) -> bytes:
        return data

    page = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", f"Content-Length: {FORM_BYTES}", body=body)
    assert page.status == 401


async def test_an_empty_form_is_a_failed_login(ctx: ServerContext) -> None:
    lock = locked(ctx, page="$error")

    async def body(size: int) -> bytes:
        return b""

    page = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", body=body)
    assert (page.status, page.body) == (401, b"Wrong username or password.")


async def test_a_form_with_too_many_fields_carries_none(ctx: ServerContext) -> None:
    lock = locked(ctx, page="$error")
    length, body = posted({f"f{n}": "x" for n in range(FORM_FIELDS)} | {"username": "alice", "password": "pw"})
    page = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
    assert page.status == 401
    length, body = posted({f"f{n}": "x" for n in range(FORM_FIELDS - 2)} | {"username": "alice", "password": "pw"})
    assert (await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)).status == 303


async def test_a_visitor_elsewhere_is_sent_home_with_a_challenge(ctx: ServerContext) -> None:
    lock = locked(ctx)
    sent = await ask(ctx, lock, "GET", OTHER, "/x?y=1")
    location = urlsplit(sent.header("Location") or "")
    assert (sent.status, location.scheme, location.netloc, location.path) == (
        303, "http", HOME, "/_wildburrow/login/vouch",
    )  # fmt: skip
    query = {key: values[0] for key, values in parse_qs(location.query).items()}
    [pending] = sent.cookies()
    name, _, rest = pending.partition("=")
    value, _, attributes = rest.partition("; ")
    tries, _, verifier = value.partition(".")
    assert (name, tries, attributes) == ("wildburrow-pending", "1", "Path=/; HttpOnly; SameSite=Lax; Max-Age=600")
    assert query == {"host": OTHER, "to": "/x?y=1", "challenge": challenge(verifier)}
    again = await ask(ctx, lock, "GET", OTHER, "/x", f"Cookie: wildburrow-pending=2.{verifier}")
    assert again.cookies()[0].startswith("wildburrow-pending=3.")


async def test_a_browser_that_keeps_no_cookies_is_told_after_a_few_rounds(ctx: ServerContext) -> None:
    lock = locked(ctx, message_page="$heading")
    stuck = await ask(ctx, lock, "GET", OTHER, "/x", f"Cookie: wildburrow-pending={MAX_TRIES}.v")
    assert (stuck.status, stuck.body) == (403, b"Couldn&#x27;t log you in here")
    assert stuck.cookies() == ["wildburrow-pending=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"]
    restarted = await ask(ctx, lock, "GET", OTHER, "/x", "Cookie: wildburrow-pending=x.v")
    assert restarted.cookies()[0].startswith("wildburrow-pending=1.")


async def test_the_home_vouches_only_for_hosts_of_its_own_tunnel(ctx: ServerContext) -> None:
    lock = locked(ctx)
    other = FakeTunnel(ALICE)
    ctx.lock(other, ["bar"], {"secret": SECRET_TEXT.replace("A", "B", 1), "users": {"x": "y"}}, Changes())
    bound(ctx, other, "bar")
    bound(ctx, FakeTunnel(ALICE), "open")
    home = logged_in(lock, HOME)
    asked = challenge(VERIFIER)

    async def vouched(host: str, to: str, carried: str) -> str | None:
        query = urlencode({"host": host, "to": to, "challenge": carried})
        return (await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/vouch?{query}", home)).header("Location")

    assert (await vouched(OTHER, "/x", asked) or "").startswith(f"http://{OTHER}/_wildburrow/login/claim?code=")
    for host, to, carried, landing in [
        ("bar.example.com", "/x", asked, "/x"),
        ("open.example.com", "/x", asked, "/x"),
        ("deep.a.foo.example.com", "/x", asked, "/x"),
        ("nowhere.org", "/x", asked, "/x"),
        (HOME, "/x", asked, "/x"),
        (OTHER, "//evil", asked, "/"),
        (OTHER, "/x", asked[:-1], "/x"),
    ]:
        assert await vouched(host, to, carried) == landing


async def test_a_claimed_code_logs_in_on_its_host(ctx: ServerContext) -> None:
    lock = locked(ctx, settings={"expires": "1h"})
    query = urlencode({"host": OTHER, "to": "/x", "challenge": challenge(VERIFIER)})
    sent = await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/vouch?{query}", logged_in(lock, HOME, until=NOW * 2))
    claim = urlsplit(sent.header("Location") or "")
    target = f"{claim.path}?{claim.query}"
    landed = await ask(ctx, lock, "GET", OTHER, target, f"Cookie: x=1; wildburrow-pending=1.{VERIFIER}")
    assert (landed.status, landed.header("Location")) == (303, "/x")
    [cookie, cleared] = landed.cookies()
    assert cookie.startswith(f"wildburrow=password:alice.{NOW * 2}.")
    assert cleared == "wildburrow-pending=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    assert lock.entries[entry_id(PASSWORD, "alice")].seen is not None


async def test_a_claim_without_its_verifier_starts_over(ctx: ServerContext) -> None:
    lock = locked(ctx)
    for headers, to, landing in [((), "/x", "/x"), (("Cookie: wildburrow-pending=1",), "/y", "/y"), ((), "//e", "/")]:
        sent = await ask(ctx, lock, "GET", OTHER, f"/_wildburrow/login/claim?code=c&to={to}", *headers)
        assert (sent.status, sent.header("Location"), sent.cookies()) == (303, landing, [])
    assert (await ask(ctx, lock, "GET", OTHER, "/_wildburrow/login/claim")).header("Location") == "/"


@pytest.mark.parametrize(
    ("method", "host", "target", "status"),
    [
        ("POST", OTHER, "/_wildburrow/login/claim", 405),
        ("PUT", HOME, "/_wildburrow/login", 405),
        ("POST", HOME, "/_wildburrow/login/vouch", 405),
        ("GET", HOME, "/_wildburrow/login/claim", 404),
        ("GET", HOME, "/_wildburrow/login/other", 404),
        ("GET", OTHER, "/_wildburrow/login", 404),
        ("GET", OTHER, "/_wildburrow/login/vouch", 404),
        ("POST", OTHER, "/api", 401),
        ("DELETE", HOME, "/api", 401),
        ("PUT", HOME, "/_wildburrow/login/link/x", 410),
    ],
)
async def test_what_the_lock_turns_away(ctx: ServerContext, method: str, host: str, target: str, status: int) -> None:
    lock = locked(ctx)
    assert (await ask(ctx, lock, method, host, target)).status == status


async def test_paths_that_only_look_like_the_lock_reach_the_app(ctx: ServerContext) -> None:
    lock = locked(ctx)
    outcome = await gate.guard(ctx, lock, request("GET", HOME, "/_wildburrow/loginx", logged_in(lock, HOME)), nothing)
    assert isinstance(outcome, Admitted)


async def test_a_logged_in_request_reaches_the_app_without_the_locks_own_headers(ctx: ServerContext) -> None:
    lock = locked(ctx)
    cookie = lock.cookie(OTHER, lock.entries[entry_id(PASSWORD, "alice")], 0)
    headers = (
        f"Cookie: a=1; wildburrow={cookie}; ; wildburrow-pending=1.v; b=2",
        "Cookie: wildburrow-pending=1.v",
        "x-wildburrow-user: root",
        "Accept: */*",
    )
    outcome = await gate.guard(ctx, lock, request("GET", OTHER, "/x", *headers), nothing)
    assert isinstance(outcome, Admitted)
    assert (
        outcome.head
        == (
            f"GET /x HTTP/1.1\r\nHost: {OTHER}\r\nCookie: a=1; b=2\r\nAccept: */*\r\nX-Wildburrow-User: alice\r\n\r\n"
        ).encode()
    )
    assert lock.entries[entry_id(PASSWORD, "alice")].seen is not None


async def test_a_cookie_for_another_host_lets_no_one_in(ctx: ServerContext) -> None:
    lock = locked(ctx)
    assert (await ask(ctx, lock, "GET", OTHER, "/x", logged_in(lock, HOME).replace(HOME, OTHER))).status == 303


@pytest.mark.parametrize(
    ("given", "status"),
    [("alice:pw", None), ("alice:pw:", 401), ("alice", 401), (":pw", 401), ("bob:pw", 401)],
)
async def test_scripts_log_in_with_the_header(ctx: ServerContext, given: str, status: int | None) -> None:
    lock = locked(ctx)
    outcome = await gate.guard(ctx, lock, request("GET", OTHER, "/x", f"X-Wildburrow-Auth: {given}"), nothing)
    if status is None:
        assert isinstance(outcome, Admitted)
        assert outcome.head.endswith(b"X-Wildburrow-User: alice\r\n\r\n")
        assert b"Auth" not in outcome.head
    else:
        assert isinstance(outcome, bytes)
        answer = Answer(outcome)
        assert (answer.status, answer.body) == (401, b"X-Wildburrow-Auth: Wrong username or password.\n")


async def test_the_header_is_slowed_down_too(ctx: ServerContext) -> None:
    ctx.locking = Locking(attempts=1)
    lock = locked(ctx)
    await ask(ctx, lock, "GET", OTHER, "/x", "X-Wildburrow-Auth: alice:x")
    answer = await ask(ctx, lock, "GET", OTHER, "/x", "X-Wildburrow-Auth: alice:pw")
    assert (answer.status, answer.body) == (429, b"Too many tries. Wait a minute, then try again.\n")


async def test_a_non_get_without_a_login_is_plainly_refused(ctx: ServerContext) -> None:
    lock = locked(ctx)
    answer = await ask(ctx, lock, "POST", OTHER, "/api")
    assert (answer.status, answer.body, answer.header("Content-Type")) == (
        401, b"This address needs a login.\n", "text/plain; charset=utf-8",
    )  # fmt: skip


def link_key(lock: Lock, host: str = "", path: str = "/") -> str:
    return lock.mint("bob", host, path, None, 1)


async def test_a_link_asks_for_a_click_first(ctx: ServerContext) -> None:
    lock = locked(ctx, link_page="$title $action")
    key = link_key(lock)
    for method in ("GET", "HEAD"):
        page = await ask(ctx, lock, method, HOME, f"/_wildburrow/login/link/{key}?x=1")
        assert (page.status, page.body) == (200, f"{HOME} /_wildburrow/login/link/{key}".encode())
    assert lock.entries[entry_id(LINK, "bob")].used is None
    landed = await ask(ctx, lock, "POST", HOME, f"/_wildburrow/login/link/{key}")
    assert (landed.status, landed.header("Location")) == (303, "/")
    assert landed.cookies()[0].startswith("wildburrow=link:bob.0.")


async def test_a_link_to_another_host_says_so_and_lands_there(ctx: ServerContext) -> None:
    lock = locked(ctx, link_page="$title")
    key = link_key(lock, OTHER, "/deep?x=1")
    assert (await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/link/{key}")).body == OTHER.encode()
    landed = await ask(ctx, lock, "POST", HOME, f"/_wildburrow/login/link/{key}")
    assert landed.header("Location") == f"http://{OTHER}/deep?x=1"


async def test_a_link_to_a_host_the_tunnel_lost_lands_at_home(ctx: ServerContext) -> None:
    lock = locked(ctx, names=("foo",))
    for host in ("gone.example.com", HOME):
        key = lock.mint(f"to-{host}", host, "/p", None, 1)
        assert (await ask(ctx, lock, "POST", HOME, f"/_wildburrow/login/link/{key}")).header("Location") == "/p"


async def test_a_link_without_a_click_opens_on_get_only(ctx: ServerContext) -> None:
    lock = locked(ctx, settings={"confirm_links": False}, link_page="page")
    key = link_key(lock)
    assert (await ask(ctx, lock, "HEAD", HOME, f"/_wildburrow/login/link/{key}")).body == b"page"
    assert (await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/link/{key}")).status == 303


async def test_a_used_link_sends_its_holder_home_and_tells_others(ctx: ServerContext) -> None:
    lock = locked(ctx, message_page="$heading|$message")
    key = link_key(lock)
    await ask(ctx, lock, "POST", HOME, f"/_wildburrow/login/link/{key}")
    gone = await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/link/{key}")
    assert (gone.status, gone.body) == (
        410, b"This link can&#x27;t be used|It was already used, or it has ended. Ask whoever shared it for a new one.",
    )  # fmt: skip
    back = await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/link/{key}", logged_in(lock, HOME, "bob"))
    assert (back.status, back.header("Location"), back.cookies()) == (303, "/", [])


async def test_the_domain_homes_locks_on_wildcards(ctx: ServerContext) -> None:
    lock = locked(ctx, names=("*.foo",), message_page="$heading")
    prefix = lock.prefix
    page = await gate.home(ctx, request("GET", "example.com", prefix), nothing)
    assert Answer(page).status == 401
    length, body = posted({"username": "alice", "password": "pw"})
    inside = Answer(await gate.home(ctx, request("POST", "example.com", prefix, length), body))
    assert (inside.status, inside.body) == (200, b"You&#x27;re in")
    assert inside.cookies()[0].startswith(f"wildburrow-{lock.id}=password:alice.0.")
    key = link_key(lock)
    opened = Answer(await gate.home(ctx, request("POST", "example.com", f"{prefix}/link/{key}"), nothing))
    assert (opened.status, opened.body) == (200, b"You&#x27;re in")
    again = Answer(
        await gate.home(
            ctx,
            request(
                "GET",
                "example.com",
                f"{prefix}/link/{key}",
                logged_in(lock, "example.com", "bob").replace("wildburrow=", f"wildburrow-{lock.id}="),
            ),
            nothing,
        )
    )
    assert again.body == b"You&#x27;re in"


@pytest.mark.parametrize(
    "path", ["/_wildburrow/lock/unknown", "/_wildburrow/lock/", "/_wildburrow/lock/ID/", "/_wildburrow/lock/ID/x"]
)
async def test_the_domain_knows_only_its_own_locks(ctx: ServerContext, path: str) -> None:
    homed = locked(ctx, names=("*.foo",))
    named = locked(ctx, names=("bar",), secret=SECRET_TEXT.replace("A", "C", 1))
    assert (
        Answer(await gate.home(ctx, request("GET", "example.com", path.replace("ID", homed.id)), nothing)).status == 404
    )
    assert (
        Answer(await gate.home(ctx, request("GET", "example.com", f"/_wildburrow/lock/{named.id}"), nothing)).status
        == 404
    )


async def test_a_lock_with_only_links_shows_no_form(ctx: ServerContext) -> None:
    lock = locked(ctx, users={}, mint=[{"label": "bob"}], message_page="$heading|$message")
    page = await ask(ctx, lock, "GET", HOME, "/")
    assert (page.status, page.body) == (401, b"This page is private|Ask whoever shared it for an invite link.")
    lock2 = locked(ctx, names=("bar",), secret=SECRET_TEXT.replace("A", "D", 1), message_page="x")
    lock2.end("alice")
    assert (await ask(ctx, lock2, "GET", "bar.example.com", "/")).body == b"x"


def test_unchanged_settings_keep_the_lock_as_the_server_made_it() -> None:
    assert LockSettings() == DEFAULTS
    assert digest("x") == digest("x")


async def test_a_link_takes_only_a_look_or_a_click(ctx: ServerContext) -> None:
    lock = locked(ctx)
    key = link_key(lock)
    assert (await ask(ctx, lock, "PUT", HOME, f"/_wildburrow/login/link/{key}")).status == 405
    assert lock.entries[entry_id(LINK, "bob")].used is None


async def test_a_form_missing_its_fields_logs_no_one_in(ctx: ServerContext) -> None:
    lock = locked(ctx, users={"XXXX": "XXXX"})

    async def body(size: int) -> bytes:
        return b""

    assert (await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", body=body)).status == 401


async def test_a_verifier_is_everything_after_the_count(ctx: ServerContext) -> None:
    lock = locked(ctx)
    query = urlencode({"host": OTHER, "to": "/x", "challenge": challenge("a.b")})
    sent = await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/vouch?{query}", logged_in(lock, HOME))
    claim = urlsplit(sent.header("Location") or "")
    target = f"{claim.path}?{claim.query}"
    assert (await ask(ctx, lock, "GET", OTHER, target)).cookies() == []
    landed = await ask(ctx, lock, "GET", OTHER, target, "Cookie: wildburrow-pending=1.a.b")
    assert len(landed.cookies()) == 2
    again = await ask(ctx, lock, "GET", OTHER, "/x", "Cookie: wildburrow-pending=2.a.b")
    assert again.cookies()[0].startswith("wildburrow-pending=3.")


async def test_a_claim_without_a_code_starts_over(ctx: ServerContext) -> None:
    lock = locked(ctx)
    sent = await ask(
        ctx, lock, "GET", OTHER, "/_wildburrow/login/claim?to=/y", f"Cookie: wildburrow-pending=1.{VERIFIER}"
    )
    assert (sent.header("Location"), sent.cookies()) == ("/y", [])


async def test_the_lock_takes_out_its_cookies_whatever_their_value(ctx: ServerContext) -> None:
    lock = locked(ctx)
    cookie = lock.cookie(OTHER, lock.entries[entry_id(PASSWORD, "alice")], 0)
    headers = (f"Cookie: wildburrow={cookie}; wildburrow-pending=1.v=x; keep=a=b",)
    outcome = await gate.guard(ctx, lock, request("GET", OTHER, "/x", *headers), nothing)
    assert isinstance(outcome, Admitted)
    assert b"Cookie: keep=a=b\r\n" in outcome.head


async def test_a_password_may_hold_a_colon(ctx: ServerContext) -> None:
    lock = locked(ctx, users={"alice": "p:w"})
    outcome = await gate.guard(ctx, lock, request("GET", OTHER, "/x", "X-Wildburrow-Auth: alice:p:w"), nothing)
    assert isinstance(outcome, Admitted)


async def test_plain_refusals_are_kept_private(ctx: ServerContext) -> None:
    lock = locked(ctx)
    answer = await ask(ctx, lock, "POST", OTHER, "/api")
    assert answer.headers[:3] == [
        ("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"), ("X-Content-Type-Options", "nosniff"),
    ]  # fmt: skip


async def test_a_form_that_stalls_runs_out_of_time(ctx: ServerContext) -> None:
    locked(ctx)
    raw = f"POST /_wildburrow/login HTTP/1.1\r\nHost: {HOME}\r\nContent-Length: 10\r\n\r\nabc".encode()
    async with running(ctx) as edge:
        async with asyncio.timeout(1):
            reply, _ = await exchange("127.0.0.1", edge.port, raw)
    assert reply.startswith(b"HTTP/1.1 400 ")


async def test_a_failed_login_still_says_where_the_visitor_is_going(ctx: ServerContext) -> None:
    ctx.locking = Locking(attempts=2)
    lock = locked(ctx, page="$title|$error")
    handoff = {"host": OTHER, "to": "/x", "challenge": challenge(VERIFIER)}
    for status, error in ((401, "Wrong username or password."), (401, "Wrong username or password."),
                          (429, "Too many tries. Wait a minute, then try again.")):  # fmt: skip
        length, body = posted({**handoff, "username": "alice", "password": "nope"})
        page = await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
        assert (page.status, page.body) == (status, f"{OTHER}|{error}".encode())


class Written:
    """What the gate writes in the server's record, by who and how, without the request it came with."""

    def __init__(self, ctx: ServerContext, monkeypatch: pytest.MonkeyPatch) -> None:
        self.seen: list[tuple[Any, ...]] = []
        record = ctx.record
        monkeypatch.setattr(record, "login_attempt", self.login_attempt)
        monkeypatch.setattr(record, "link_opened", self.link_opened)
        monkeypatch.setattr(record, "redeemed", self.redeemed)

    def login_attempt(
        self, lock: Lock, via: str, label: str | None, entry: Any, peer: Any, request: Any, reason: str | None
    ) -> None:
        self.seen.append(("login", via, label, entry and entry.label, reason))

    def link_opened(self, lock: Lock, entry: Any, peer: Any, request: Any, used: bool) -> None:
        self.seen.append(("link", entry.label, used))

    def redeemed(self, code: str) -> None:
        self.seen.append(("redeemed", code))


@pytest.fixture
def written(ctx: ServerContext, monkeypatch: pytest.MonkeyPatch) -> Written:
    return Written(ctx, monkeypatch)


async def test_every_form_login_is_recorded_with_who_tried(ctx: ServerContext, written: Written) -> None:
    ctx.locking = Locking(attempts=1)
    lock = locked(ctx)
    for form in ({"username": "alice", "password": "pw"}, {"username": "alice", "password": "x"}, {"password": "x"}):
        length, body = posted(form)
        await ask(ctx, lock, "POST", HOME, "/_wildburrow/login", length, body=body)
    assert written.seen == [
        ("login", "form", "alice", "alice", None),
        ("login", "form", "alice", None, "wrong-password"),
        ("login", "form", "", None, "limited"),
    ]


async def test_every_header_login_is_recorded_with_who_tried(ctx: ServerContext, written: Written) -> None:
    ctx.locking = Locking(attempts=1)
    lock = locked(ctx)
    for given in ("alice:pw", "bob:x", "carol:pw"):
        await gate.guard(ctx, lock, request("GET", OTHER, "/x", f"X-Wildburrow-Auth: {given}"), nothing)
    assert written.seen == [
        ("login", "header", "alice", "alice", None),
        ("login", "header", "bob", None, "wrong-password"),
        ("login", "header", "carol", None, "limited"),
    ]


async def test_a_link_is_recorded_when_shown_and_when_used(ctx: ServerContext, written: Written) -> None:
    lock = locked(ctx)
    key = link_key(lock)
    await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/link/{key}")
    await ask(ctx, lock, "POST", HOME, f"/_wildburrow/login/link/{key}")
    assert written.seen == [("link", "bob", False), ("link", "bob", True), ("login", "link", "bob", "bob", None)]


async def test_a_claimed_code_is_recorded_by_its_digest(ctx: ServerContext, written: Written) -> None:
    lock = locked(ctx)
    query = urlencode({"host": OTHER, "to": "/x", "challenge": challenge(VERIFIER)})
    sent = await ask(ctx, lock, "GET", HOME, f"/_wildburrow/login/vouch?{query}", logged_in(lock, HOME))
    claim = urlsplit(sent.header("Location") or "")
    [code] = parse_qs(claim.query)["code"]
    await ask(ctx, lock, "GET", OTHER, f"{claim.path}?{claim.query}", f"Cookie: wildburrow-pending=1.{VERIFIER}")
    assert written.seen == [("redeemed", hashlib.sha256(code.encode()).hexdigest())]
