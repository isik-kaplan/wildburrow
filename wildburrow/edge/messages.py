"""Reading a visitor's request head and writing the responses the server answers itself."""

import re
from dataclasses import dataclass
from http import HTTPStatus

from wildburrow.core.types import Peer

HEAD_END = b"\r\n\r\n"
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# A request no one has said the sender of yet.
NOWHERE = Peer("", 0)
VERSION = re.compile(r"HTTP/1\.[01]")
WHITESPACE = " \t"
TEXT = "text/plain; charset=utf-8"
JSON = "application/json"
# Asks search engines not to index a page or follow its links.
NOINDEX = ("X-Robots-Tag", "noindex, nofollow")


class BadRequest(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Request:
    host: str
    target: str
    method: str = "GET"
    line: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    # Who sent it, which the edge fills in once it's parsed.
    peer: Peer = NOWHERE

    def path(self) -> str:
        return self.target.partition("?")[0]

    def query(self) -> str:
        return self.target.partition("?")[2]

    def header(self, name: str) -> str | None:
        """The first header named `name`, which is lowercase."""
        return next((value for key, value in self.headers if key.lower() == name), None)

    def cookies(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for key, value in self.headers:
            if key.lower() == "cookie":
                for pair in value.split(";"):
                    name, _, content = pair.strip().partition("=")
                    found.setdefault(name, content)
        return found

    def head(self, headers: list[tuple[str, str]]) -> bytes:
        """This request's head with `headers` in place of its own."""
        return "\r\n".join([self.line, *(f"{key}: {value}" for key, value in headers)]).encode() + HEAD_END


def parse_request(head: bytes) -> Request:
    if not head.isascii():
        raise BadRequest("non-ascii request head")
    text = head.decode()
    request_line, *header_lines = text.removesuffix("\r\n\r\n").split("\r\n")
    parts = request_line.split(" ")
    if len(parts) != 3 or not TOKEN.fullmatch(parts[0]) or not VERSION.fullmatch(parts[2]):
        raise BadRequest("malformed request line")
    if not parts[1].startswith("/"):
        raise BadRequest("only origin-form request targets are accepted")
    hosts, headers = [], []
    for line in header_lines:
        name, sep, value = line.partition(":")
        if not sep or not TOKEN.fullmatch(name):
            raise BadRequest("malformed header line")
        headers.append((name, value.strip(WHITESPACE)))
        if name.lower() == "host":
            hosts.append(value.strip(WHITESPACE))
    if len(hosts) != 1:
        raise BadRequest("exactly one Host header is required")
    host, _, port = hosts[0].partition(":")
    if port and not port.isdigit():
        raise BadRequest("malformed Host port")
    return Request(host.lower(), parts[1], parts[0], request_line, tuple(headers))


def response(
    status: HTTPStatus,
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    body: bytes | None = None,
    content_type: str = TEXT,
) -> bytes:
    body = f"{status.value} {status.phrase}\n".encode() if body is None else body
    pairs = headers.items() if isinstance(headers, dict) else headers or []
    lines = [f"HTTP/1.1 {status.value} {status.phrase}"]
    lines += [f"{key}: {value}" for key, value in pairs]
    lines += [f"Content-Length: {len(body)}", f"Content-Type: {content_type}", "Connection: close", ": ".join(NOINDEX)]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body
