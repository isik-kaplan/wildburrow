"""What `--lock` and `--link` ask the server for, kept by the client so a reconnect keeps every login and link."""

import base64
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from wildburrow.locks import SECRET_BYTES

TYPED = "(the one you typed)"


def new_secret() -> str:
    # token_bytes(None) asks for the default of 32 bytes, so that mutant is the same program.
    return base64.urlsafe_b64encode(secrets.token_bytes(SECRET_BYTES)).decode()  # pragma: no mutate


@dataclass
class LockRequest:
    # Passwords by username, and the usernames whose password was typed rather than given or made up.
    users: dict[str, str]
    typed: frozenset[str] = frozenset()
    # Links for the server to mint on the first connection: their labels and when they stop working.
    mint: list[dict[str, Any]] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)
    secret: str = field(default_factory=new_secret, repr=False)
    # The links the server minted and which logins ended, as it last said; sent back on reconnecting.
    state: dict[str, Any] = field(default_factory=lambda: {"links": {}, "ended": []})
    announced: bool = False

    def spec(self) -> dict[str, Any]:
        return {
            "secret": self.secret,
            "users": self.users,
            "links": self.state["links"],
            "ended": self.state["ended"],
            "mint": self.mint,
            "settings": self.settings,
        }

    def locked(self, message: dict[str, Any], out: Callable[[str], None]) -> None:
        """Takes the server's word that the tunnel is locked; the first time, prints how to get in."""
        self.state = message["state"]
        self.mint = []
        if self.announced:
            return
        self.announced = True
        rows = [
            (username, f"password: {TYPED if username in self.typed else password}")
            for username, password in self.users.items()
        ]
        rows += [(str(link["label"]), str(link["url"])) for link in message["links"]]
        width = max(len(label) for label, _ in rows)
        out("locked:")
        for label, text in rows:
            out(f"  {label.ljust(width)}  {text}")
