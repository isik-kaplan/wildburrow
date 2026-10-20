import json
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow import protocol
from wildburrow.cli.client import AUTH_BY_TRANSPORT
from wildburrow.client import discovery
from wildburrow.client.discovery import Published, parse

# Taken before the unit tests' own server replaces it.
FETCH = discovery.fetch
DOCUMENT = {
    "version": "9.9.9",
    "transports": {"ssh": {"auth": ["password", "key"], "port": 2200}, "websocket": {"auth": ["key", "token"]}},
    "defaults": {"transport": "websocket", "auth": "token"},
}
EXPECTED = Published({"ssh": ("password", "key"), "websocket": ("key", "token")}, "websocket", "token", 2200)

type Answer = Callable[[BaseHTTPRequestHandler], None]


def send(status: int, body: bytes = b"", **headers: str) -> Answer:
    def answer(request: BaseHTTPRequestHandler) -> None:
        request.send_response(status)
        for name, value in headers.items():
            request.send_header(name, value)
        request.send_header("Content-Length", str(len(body)))
        request.end_headers()
        request.wfile.write(body)

    return answer


class Site:
    def __init__(self) -> None:
        self.answers: dict[str, Answer] = {}
        self.seen: list[tuple[str, str]] = []

    def handler(self) -> type[BaseHTTPRequestHandler]:
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                # The path as sent: http.server's own folds a leading // away.
                site.seen.append((self.headers["Host"], self.requestline.split(" ")[1]))
                site.answers.get(self.path, send(404))(self)

            def log_message(self, *args: Any) -> None:
                pass

        return Handler


@pytest.fixture
def site() -> Iterator[tuple[Site, str]]:
    site = Site()
    server = ThreadingHTTPServer(("127.0.0.1", 0), site.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield site, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_fetches_the_document_under_the_base(site: tuple[Site, str]) -> None:
    pages, base = site
    pages.answers[protocol.INFO_PATH] = send(200, json.dumps(DOCUMENT).encode())
    assert FETCH(base + "/", AUTH_BY_TRANSPORT) == EXPECTED
    assert pages.seen == [(base.removeprefix("http://"), protocol.INFO_PATH)]


@pytest.mark.parametrize(
    "answer",
    [
        send(404),
        send(500, b"{}"),
        send(200, b"not json"),
        send(200, json.dumps(DOCUMENT).encode() + b" " * discovery.LIMIT),
    ],
    ids=["missing", "failing", "garbled", "oversized"],
)
def test_anything_amiss_is_no_document(site: tuple[Site, str], answer: Answer) -> None:
    pages, base = site
    pages.answers[protocol.INFO_PATH] = answer
    assert FETCH(base, AUTH_BY_TRANSPORT) is None


def test_a_document_at_the_size_limit_is_read(site: tuple[Site, str]) -> None:
    pages, base = site
    body = json.dumps(DOCUMENT).encode()
    pages.answers[protocol.INFO_PATH] = send(200, b" " * (discovery.LIMIT - len(body)) + body)
    assert FETCH(base, AUTH_BY_TRANSPORT) == EXPECTED


def test_a_redirect_is_not_followed(site: tuple[Site, str]) -> None:
    pages, base = site
    pages.answers[protocol.INFO_PATH] = send(302, Location="/elsewhere")
    pages.answers["/elsewhere"] = send(200, json.dumps(DOCUMENT).encode())
    assert FETCH(base, AUTH_BY_TRANSPORT) is None
    assert [path for _, path in pages.seen] == [protocol.INFO_PATH]


def test_goes_through_the_proxy_from_the_environment(site: tuple[Site, str], monkeypatch: pytest.MonkeyPatch) -> None:
    pages, base = site
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("http_proxy", base)
    url = f"http://tunnel.invalid{protocol.INFO_PATH}"
    pages.answers[url] = send(200, json.dumps(DOCUMENT).encode())
    assert FETCH("http://tunnel.invalid", AUTH_BY_TRANSPORT) == EXPECTED
    assert pages.seen == [("tunnel.invalid", url)]


@pytest.mark.parametrize("base", ["http://127.0.0.1:9", "not a url"])
def test_an_unreachable_server_is_no_document(base: str) -> None:
    assert FETCH(base, AUTH_BY_TRANSPORT) is None


def document(**changes: Any) -> bytes:
    return json.dumps(DOCUMENT | changes).encode()


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            document(transports={"ssh": {"auth": ["key"]}, "carrier-pigeon": {"auth": ["key"]}}),
            Published({"ssh": ("key",)}, "ssh", "key", None),
        ),
        (
            document(transports={"websocket": {"auth": ["telepathy", "key"]}}),
            Published({"websocket": ("key",)}, "websocket", "key", None),
        ),
        (
            document(transports={"ssh": {"auth": ["token"]}, "websocket": {"auth": ["key"]}}),
            Published({"websocket": ("key",)}, "websocket", "key", None),
        ),
        (
            document(defaults={"transport": "carrier-pigeon", "auth": "telepathy"}),
            Published(EXPECTED.auth, "ssh", "password", 2200),
        ),
        (document(defaults={"transport": "websocket", "auth": "password"}), EXPECTED.__replace__(method="key")),
        (document(defaults={}), Published(EXPECTED.auth, "ssh", "password", 2200)),
        (
            document(transports={"ssh": {"auth": ["key"], "port": 65535}}),
            Published({"ssh": ("key",)}, "ssh", "key", 65535),
        ),
        (document(transports={"ssh": {"auth": ["key"], "port": 1}}), Published({"ssh": ("key",)}, "ssh", "key", 1)),
    ],
    ids=[
        "unknown-transport",
        "unknown-method",
        "no-usable-method",
        "unknown-defaults",
        "default-not-offered",
        "no-defaults",
        "highest-port",
        "lowest-port",
    ],
)
def test_parse_keeps_what_this_client_knows(data: bytes, expected: Published) -> None:
    assert parse(data, AUTH_BY_TRANSPORT) == expected


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b'"text"',
        document(transports={}),
        document(transports={"carrier-pigeon": {"auth": ["key"]}}),
        document(transports=[]),
        document(transports={"ssh": {"auth": "key"}}),
        document(transports={"ssh": {}}),
        document(defaults=[]),
        document(defaults={"transport": []}),
        *(document(transports={"ssh": {"auth": ["key"], "port": port}}) for port in (0, 65536, "22", True, 2.5)),
        b"[" * 100_000,
        b"\xff",
    ],
)
def test_parse_refuses_what_it_cannot_use(data: bytes) -> None:
    assert parse(data, AUTH_BY_TRANSPORT) is None


JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=12),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=12), inner, max_size=4),
    max_leaves=20,
)


@given(st.dictionaries(st.sampled_from(["transports", "defaults", "version"]), JSON) | JSON)
def test_parse_never_fails_on_any_json(value: Any) -> None:
    published = parse(json.dumps(value).encode(), AUTH_BY_TRANSPORT)
    if published is not None:
        assert published.method in published.auth[published.transport]


def test_a_transport_other_than_the_default_starts_from_its_first_method() -> None:
    assert EXPECTED.method_for("websocket") == "token"
    assert EXPECTED.method_for("ssh") == "password"


def test_a_server_that_never_answers_is_no_document(site: tuple[Site, str], monkeypatch: pytest.MonkeyPatch) -> None:
    pages, base = site
    late = send(200, json.dumps(DOCUMENT).encode())
    pages.answers[protocol.INFO_PATH] = lambda request: (time.sleep(0.5), late(request))
    monkeypatch.setattr(discovery, "TIMEOUT", 0.1)
    assert FETCH(base, AUTH_BY_TRANSPORT) is None
