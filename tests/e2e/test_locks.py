import asyncio
import html
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import pytest

from tests.conftest import DOMAIN, TIMEOUT, Backend, Credentials, Running, StartServer, http
from tests.e2e.test_websocket import TOKEN, client_config, local, start_client, stop
from wildburrow.client import websocket
from wildburrow.client.locking import LockRequest
from wildburrow.tokens import digest

pytestmark = pytest.mark.e2e

MAX_REDIRECTS = 10
HASHES = f"ci:{digest(TOKEN)}"


@pytest.fixture
def env() -> dict[str, str]:
    return {"WILDBURROW_TRANSPORTS": "websocket", "WILDBURROW_AUTH": "token", "WILDBURROW_AUTH_TOKEN_HASHES": HASHES}


@dataclass
class Reply:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        return next((value for key, value in self.headers if key.lower() == name.lower()), None)

    def set_cookies(self) -> list[str]:
        return [value for key, value in self.headers if key.lower() == "set-cookie"]


def parse(raw: bytes) -> Reply:
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line, *lines = head.decode().split("\r\n")
    headers = [(key, value.strip()) for key, _, value in (line.partition(":") for line in lines)]
    return Reply(int(status_line.split(" ")[1]), headers, body)


@dataclass
class Browser:
    """Keeps each host's cookies as a browser would and follows redirects, every host reached on the one edge."""

    port: int
    jar: dict[str, dict[str, str]] = field(default_factory=dict)
    visited: list[str] = field(default_factory=list)

    async def send(self, url: str, method: str = "GET", form: dict[str, str] | None = None, **headers: str) -> Reply:
        parts = urlsplit(url)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        lines = [f"{method} {target} HTTP/1.1", f"Host: {parts.hostname}"]
        if cookies := self.jar.get(parts.hostname or "", {}):
            lines.append("Cookie: " + "; ".join(f"{name}={value}" for name, value in cookies.items()))
        lines += [f"{name.replace('_', '-')}: {value}" for name, value in headers.items()]
        body = b""
        if form is not None:
            body = urlencode(form).encode()
            lines += ["Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(body)}"]
        reply = parse(await http(self.port, ("\r\n".join(lines) + "\r\n\r\n").encode() + body))
        self.visited.append(f"{method} {url} {reply.status}")
        for cookie in reply.set_cookies():
            pair, *attributes = cookie.split("; ")
            name, _, value = pair.partition("=")
            if "Max-Age=0" in attributes:
                self.jar.get(parts.hostname or "", {}).pop(name, None)
            else:
                self.jar.setdefault(parts.hostname or "", {})[name] = value
        return reply

    async def visit(self, url: str, method: str = "GET", form: dict[str, str] | None = None, **headers: str) -> Reply:
        """Opens `url` and follows where it leads, as a browser would."""
        reply = await self.send(url, method, form, **headers)
        for _ in range(MAX_REDIRECTS):
            if reply.status != 303:
                return reply
            location = reply.header("Location") or ""
            if location.startswith("/"):
                parts = urlsplit(url)
                location = f"{parts.scheme}://{parts.netloc}{location}"
            url = location
            reply = await self.send(url)
        raise AssertionError(f"too many redirects: {self.visited}")


def at(name: str, path: str = "/") -> str:
    return f"http://{name}.{DOMAIN}{path}" if name else f"http://{DOMAIN}{path}"


async def locked(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str], names: list[str],
    lock: LockRequest, **server: str,
) -> tuple[Running, asyncio.Task[int], list[str]]:  # fmt: skip
    running = await start_server(**env, **server)
    task, out = start_client(running, client_config(credentials, "token"), backend.port, names, lock=lock)
    await out.wait_for("locked:")
    return running, task, out.lines


async def test_a_password_logs_in_and_the_app_is_told_who(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland"})
    running, task, _ = await locked(start_server, credentials, backend, env, ["app"], lock)
    browser = Browser(running.http_port)
    page = await browser.visit(at("app", "/bar?baz=1"))
    assert page.status == 401
    assert b'name="password"' in page.body
    assert backend.requests == []
    form = {"username": "alice", "password": "wonderland", "to": "/bar?baz=1"}
    reply = await browser.visit(at("app", "/_wildburrow/login"), "POST", form)
    assert reply.status == 200
    assert reply.body == b"GET /bar?baz=1 HTTP/1.1"
    [head] = backend.requests
    assert b"X-Wildburrow-User: alice" in head
    assert b"Cookie" not in head
    await stop(task)


def fields(page: Reply) -> dict[str, str]:
    """The hidden fields a login page carries through the login."""
    found = re.findall(r'<input type="hidden" name="([^"]*)" value="([^"]*)">', page.body.decode())
    return {html.unescape(name): html.unescape(value) for name, value in found}


def link_of(lines: list[str], label: str) -> str:
    return next(line.split()[-1] for line in lines if line.split()[:1] == [label])


async def test_one_login_covers_every_host_of_the_tunnel(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland"})
    running, task, _ = await locked(start_server, credentials, backend, env, ["foo", "*.foo"], lock)
    browser = Browser(running.http_port)
    page = await browser.visit(at("admin.foo", "/bar/baz?x=1"))
    assert page.status == 401
    assert browser.visited[1].startswith(f"GET {at('foo', '/_wildburrow/login/vouch?')}")
    assert f"to admin.foo.{DOMAIN}".encode() in page.body
    form = {**fields(page), "username": "alice", "password": "wonderland"}
    reply = await browser.visit(at("foo", "/_wildburrow/login"), "POST", form)
    assert reply.body == b"GET /bar/baz?x=1 HTTP/1.1"
    assert browser.visited[-1] == f"GET {at('admin.foo', '/bar/baz?x=1')} 200"
    for host in ("api.foo", "foo", "admin.foo"):
        assert (await browser.visit(at(host, "/next"))).body == b"GET /next HTTP/1.1"
    assert not any("POST" in step for step in browser.visited[-5:])
    assert all(b"X-Wildburrow-User: alice" in head for head in backend.requests)
    await stop(task)


async def test_a_link_logs_in_once(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({}, mint=[{"label": "link-1", "expires": None}])
    running, task, lines = await locked(start_server, credentials, backend, env, ["foo", "*.foo"], lock)
    url = link_of(lines, "link-1")
    assert url.startswith(at("foo", "/_wildburrow/login/link/"))
    [key] = [link["key"] for link in lock.state["links"].values()]
    assert lock.state == {
        "links": {"link-1": {"key": key, "host": "", "path": "/", "expires": None, "used": None}},
        "ended": [],
    }
    friend, preview = Browser(running.http_port), Browser(running.http_port)
    assert (await preview.visit(url)).status == 200
    page = await friend.visit(url)
    assert b"Continue" in page.body
    assert (await friend.visit(url, "POST")).body == b"GET / HTTP/1.1"
    assert (await friend.visit(at("api.foo", "/x"))).body == b"GET /x HTTP/1.1"
    assert b"X-Wildburrow-User: link-1" in backend.requests[-1]
    assert (await friend.visit(url)).body == b"GET / HTTP/1.1"
    assert (await preview.visit(url)).status == 410
    assert (await preview.visit(at("foo"))).status == 401
    assert lock.state["links"]["link-1"]["used"] is not None
    await stop(task)


async def test_a_tunnel_with_only_links_has_no_password_form(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({}, mint=[{"label": "bob", "expires": None}])
    running, task, _ = await locked(start_server, credentials, backend, env, ["foo"], lock)
    page = await Browser(running.http_port).visit(at("foo"))
    assert page.status == 401
    assert b"Ask whoever shared it for an invite link." in page.body
    assert b"password" not in page.body
    await stop(task)


async def test_links_can_open_without_a_click(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({}, mint=[{"label": "bob", "expires": None}], settings={"confirm_links": False})
    running, task, lines = await locked(start_server, credentials, backend, env, ["foo"], lock)
    assert (await Browser(running.http_port).visit(link_of(lines, "bob"))).body == b"GET / HTTP/1.1"
    await stop(task)


async def test_a_wildcard_only_tunnel_logs_in_on_the_servers_domain(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland"}, mint=[{"label": "link-1", "expires": None}])
    running, task, lines = await locked(start_server, credentials, backend, env, ["*.foo"], lock)
    url = link_of(lines, "link-1")
    assert url.startswith(at("", "/_wildburrow/lock/"))
    friend = Browser(running.http_port)
    landed = await friend.visit(url, "POST")
    assert (landed.status, b"You&#x27;re in" in landed.body) == (200, True)
    assert (await friend.visit(at("a.foo", "/p"))).body == b"GET /p HTTP/1.1"
    stranger = Browser(running.http_port)
    page = await stranger.visit(at("b.foo", "/q"))
    assert page.status == 401
    form = {**fields(page), "username": "alice", "password": "wonderland"}
    lock_path = urlsplit(url).path.split("/link/")[0]
    assert (await stranger.visit(at("", lock_path), "POST", form)).body == b"GET /q HTTP/1.1"
    await stop(task)


async def test_more_links_are_minted_for_a_running_tunnel(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland"})
    running, task, _ = await locked(start_server, credentials, backend, env, ["foo", "*.foo"], lock)
    config = client_config(credentials, "token")
    minted = await websocket.link(config, {"url": at("admin.foo", "/bar/baz")}, connector=local(running))
    assert minted["label"] == "link-1"
    friend = Browser(running.http_port)
    assert (await friend.visit(minted["url"], "POST")).body == b"GET /bar/baz HTTP/1.1"
    assert friend.visited[-1] == f"GET {at('admin.foo', '/bar/baz')} 200"
    assert set(lock.state["links"]) == {"link-1"}
    refused = await websocket.link(config, {"url": at("elsewhere")}, connector=local(running))
    assert refused == {"type": "linked", "error": f"no locked tunnel of yours serves 'elsewhere.{DOMAIN}'"}
    await stop(task)


async def test_ending_a_login_logs_out_whoever_used_it(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland", "bob": "builder"})
    running, task, _ = await locked(start_server, credentials, backend, env, ["foo"], lock)
    alice, bob = Browser(running.http_port), Browser(running.http_port)
    for browser, name, password in ((alice, "alice", "wonderland"), (bob, "bob", "builder")):
        await browser.visit(at("foo", "/_wildburrow/login"), "POST", {"username": name, "password": password})
    config = client_config(credentials, "token")
    [listed] = await websocket.logins(config, connector=local(running))
    assert listed["names"] == ["foo"]
    assert [(entry["who"], entry["logins"], entry["ended"]) for entry in listed["logins"]] == [
        ("alice", 1, False),
        ("bob", 1, False),
    ]
    ended = await websocket.end_login(config, "bob", connector=local(running))
    assert ended == {"type": "ended-login", "who": "bob", "ended": [["foo"]]}
    assert (await alice.visit(at("foo"))).status == 200
    assert (await bob.visit(at("foo"))).status == 401
    again = {"username": "bob", "password": "builder"}
    assert (await bob.visit(at("foo", "/_wildburrow/login"), "POST", again)).status == 401
    assert lock.state["ended"] == ["bob"]
    await stop(task)


async def test_scripts_log_in_with_a_header(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland"})
    running, task, _ = await locked(
        start_server, credentials, backend, env, ["foo"], lock, WILDBURROW_LOCK_ATTEMPTS="2"
    )
    script = Browser(running.http_port)
    reply = await script.send(at("foo"), X_Wildburrow_Auth="alice:wonderland", X_Wildburrow_User="root")
    assert reply.status == 200
    assert b"X-Wildburrow-Auth" not in backend.requests[-1]
    assert backend.requests[-1].count(b"X-Wildburrow-User") == 1
    assert b"X-Wildburrow-User: alice" in backend.requests[-1]
    for _ in range(2):
        assert (await script.send(at("foo"), X_Wildburrow_Auth="alice:wrong")).status == 401
    assert (await script.send(at("foo"), X_Wildburrow_Auth="alice:wonderland")).status == 429
    await stop(task)


async def test_a_reconnect_keeps_logins_and_used_links(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland"}, mint=[{"label": "link-1", "expires": None}])
    running, task, lines = await locked(start_server, credentials, backend, env, ["foo"], lock)
    url = link_of(lines, "link-1")
    friend = Browser(running.http_port)
    await friend.visit(url, "POST")
    await stop(task)
    async with asyncio.timeout(TIMEOUT):
        while running.server.ctx.locks:
            await asyncio.sleep(0.01)
    assert (await friend.visit(at("foo"))).status == 404
    task, out = start_client(running, client_config(credentials, "token"), backend.port, ["foo"], lock=lock)
    await out.wait_for("ready:")
    async with asyncio.timeout(TIMEOUT):
        while (await friend.visit(at("foo"))).status != 200:
            await asyncio.sleep(0.01)
    assert (await Browser(running.http_port).visit(url)).status == 410
    assert "locked:" not in out.lines
    await stop(task)


async def test_a_code_works_only_in_the_browser_it_was_made_for(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    lock = LockRequest({"alice": "wonderland"})
    running, task, _ = await locked(start_server, credentials, backend, env, ["foo", "*.foo"], lock)
    alice = Browser(running.http_port)
    page = await alice.visit(at("admin.foo", "/secret"))
    form = {**fields(page), "username": "alice", "password": "wonderland"}
    handed = await alice.send(at("foo", "/_wildburrow/login"), "POST", form)
    claim = handed.header("Location") or ""
    assert claim.startswith(at("admin.foo", "/_wildburrow/login/claim?code="))
    thief = Browser(running.http_port)
    stolen = await thief.send(claim)
    assert (stolen.status, stolen.header("Location"), stolen.set_cookies()) == (303, "/secret", [])
    assert (await alice.visit(claim)).body == b"GET /secret HTTP/1.1"
    assert (await alice.send(claim)).header("Location") == "/secret"
    assert len(backend.requests) == 1
    await stop(task)


async def test_a_client_can_dress_its_lock_its_own_way(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    own = "<html>$title $action $error $hidden</html>"
    settings = {"path": "/.in", "cookie": "pass", "user_header": "X-Who", "expires": "1h", "page": own}
    lock = LockRequest({"alice": "wonderland"}, settings=settings)
    running, task, _ = await locked(start_server, credentials, backend, env, ["foo"], lock)
    browser = Browser(running.http_port)
    page = await browser.send(at("foo", "/x"))
    assert page.body == f'<html>foo.{DOMAIN} /.in  <input type="hidden" name="to" value="/x"></html>'.encode()
    assert page.header("Content-Security-Policy") == "frame-ancestors 'none'"
    reply = await browser.send(at("foo", "/.in"), "POST", {"username": "alice", "password": "wonderland"})
    [cookie] = reply.set_cookies()
    assert cookie.startswith("pass=alice.")
    assert cookie.endswith("; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600")
    assert (await browser.visit(at("foo"))).status == 200
    assert b"X-Who: alice" in backend.requests[-1]
    await stop(task)


async def test_a_lock_the_server_cant_take_is_refused(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    running = await start_server(**env)
    lock = LockRequest({"alice": "wonderland"}, settings={"path": "nope"})
    task, out = start_client(running, client_config(credentials, "token"), backend.port, ["foo"], lock=lock)
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert await out.wait_for("rejected:") == (
        "rejected: lock: lock setting 'path': expected a path like /_wildburrow/login, got 'nope'"
    )
    assert running.server.ctx.locks == {}


async def test_a_lock_goes_with_names_it_couldnt_bind(
    start_server: StartServer, credentials: Credentials, backend: Backend, env: dict[str, str]
) -> None:
    running = await start_server(**env)
    lock = LockRequest({"alice": "wonderland"})
    task, out = start_client(running, client_config(credentials, "token"), backend.port, ["foo", "-bad"], lock=lock)
    assert await asyncio.wait_for(task, TIMEOUT) == 1
    assert (await out.wait_for("rejected:")).startswith("rejected: '-bad': ")
    assert running.server.ctx.locks == {}


async def test_locking_is_logged(
    start_server: StartServer,
    credentials: Credentials,
    backend: Backend,
    env: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, "wildburrow.transports.websocket")
    lock = LockRequest({"alice": "wonderland"})
    _, task, _ = await locked(start_server, credentials, backend, env, ["foo", "*.foo"], lock)
    assert ("wildburrow.transports.websocket", logging.INFO, "ci locked foo, *.foo") in caplog.record_tuples
    await stop(task)
