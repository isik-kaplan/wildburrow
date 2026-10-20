"""What a server publishes about logging in to it, read before `wildburrow login` saves anything."""

import json
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from wildburrow import protocol

LIMIT = 65536
TIMEOUT = 10


@dataclass(frozen=True, slots=True)
class Published:
    # Each transport this client can use, with the methods it takes, in the server's order.
    auth: dict[str, tuple[str, ...]]
    transport: str
    method: str
    ssh_port: int | None

    def method_for(self, transport: str) -> str:
        return self.method if transport == self.transport else self.auth[transport][0]


class _Refuse(urllib.request.HTTPRedirectHandler):
    # A redirect could hand the answer to another host, so it counts as no answer.
    def redirect_request(self, *args: Any) -> None:
        return None


def fetch(base: str, known: Mapping[str, Sequence[str]]) -> Published | None:
    """The document under `base`, or None when there's none to be had: an older server, or anything amiss."""
    url = base.removesuffix("/") + protocol.INFO_PATH
    try:
        with urllib.request.build_opener(_Refuse).open(url, timeout=TIMEOUT) as page:
            # One byte past the limit tells an oversized page apart; reading further would change nothing.
            data = page.read(LIMIT + 1)  # pragma: no mutate
    except urllib.error.HTTPError as refused:
        refused.close()
        return None
    except OSError, ValueError:
        return None
    return parse(data, known) if len(data) <= LIMIT else None


def parse(data: bytes, known: Mapping[str, Sequence[str]]) -> Published | None:
    """The part of a document this client understands; a newer server may offer more than it knows."""
    try:
        return _parse(json.loads(data), known)
    except ValueError, KeyError, TypeError, AttributeError, RecursionError:
        return None


def _parse(document: Any, known: Mapping[str, Sequence[str]]) -> Published | None:
    transports, defaults = document["transports"], document["defaults"]
    auth = {
        name: offered
        for name, methods in known.items()
        if name in transports and (offered := tuple(m for m in transports[name]["auth"] if m in methods))
    }
    port = transports.get("ssh", {}).get("port")
    if not auth or (port is not None and (type(port) is not int or not 0 < port < 65536)):
        return None
    transport = defaults["transport"] if defaults.get("transport") in auth else next(iter(auth))
    method = defaults["auth"] if defaults.get("auth") in auth[transport] else auth[transport][0]
    return Published(auth, transport, method, port)
