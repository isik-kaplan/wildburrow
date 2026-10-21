"""Tokens signed with an SSH key the server trusts: minted offline, checked by the server without keeping anything."""

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any

# A random token, checked against the hashes the server is given.
HASHED_PREFIX = "wb_"
HASHED_BYTES = 32
PREFIX = "wb1."
# Its own namespace, so no signature made for logging in with a key can pass as a token, or the other way round.
NAMESPACE = "wildburrow-token"
ID_BYTES = 8
ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"


@dataclass(frozen=True, slots=True)
class Grant:
    name: str
    # The names it may claim, `*` standing for one label; None for any.
    names: tuple[str, ...] | None
    # Unix seconds; None for never.
    expires: int | None
    issued: int
    id: str

    def payload(self) -> bytes:
        fields = {
            "id": self.id,
            "name": self.name,
            "names": None if self.names is None else list(self.names),
            "expires": self.expires,
            "issued": self.issued,
        }
        return json.dumps(fields, separators=(",", ":"), sort_keys=True).encode()


def new_token() -> str:
    # The only mutant left here, token_urlsafe(None), asks for the default of 32 bytes.
    return HASHED_PREFIX + secrets.token_urlsafe(HASHED_BYTES)  # pragma: no mutate


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_id() -> str:
    return secrets.token_hex(ID_BYTES)


def encode(payload: bytes, signature: bytes) -> str:
    return f"{PREFIX}{_text(payload)}.{_text(signature)}"


def decode(token: str) -> tuple[Grant, bytes, bytes]:
    """The grant, the exact bytes that were signed, and the signature; ValueError for anything else."""
    if not token.startswith(PREFIX):
        raise ValueError("not a signed token")
    parts = token.removeprefix(PREFIX).split(".")
    if len(parts) != 2:
        raise ValueError("not a signed token")
    payload, signature = _bytes(parts[0]), _bytes(parts[1])
    try:
        return _grant(json.loads(payload)), payload, signature
    except KeyError, RecursionError:
        # A token comes from anyone, so whatever is wrong with it reads as one kind of refusal.
        raise ValueError("not a grant") from None


def _grant(fields: Any) -> Grant:
    if not isinstance(fields, dict):
        raise ValueError("not a grant")
    names = fields["names"]
    if names is not None and not (isinstance(names, list) and all(isinstance(name, str) for name in names)):
        raise ValueError("names must be a list of names")
    return Grant(
        _typed(fields["name"], str),
        None if names is None else tuple(names),
        None if fields["expires"] is None else _typed(fields["expires"], int),
        _typed(fields["issued"], int),
        _typed(fields["id"], str),
    )


def unarmor(armored: str) -> bytes:
    """The signature inside `ssh-keygen -Y sign` output."""
    body = armored.strip()
    if not body.startswith(ARMOR_BEGIN) or not body.endswith(ARMOR_END):
        raise ValueError("not an armored SSH signature")
    try:
        return base64.b64decode("".join(body[len(ARMOR_BEGIN) : -len(ARMOR_END)].split()), validate=True)
    except ValueError:
        raise ValueError("signature is not valid base64") from None


def armor(signature: bytes) -> str:
    return f"{ARMOR_BEGIN}\n{base64.b64encode(signature).decode()}\n{ARMOR_END}\n"


def _typed[T](value: Any, kind: type[T]) -> T:
    # bool is an int to isinstance, and never a timestamp.
    if type(value) is not kind or not value:
        raise ValueError(f"expected {kind.__name__}, got {value!r}")
    return value


def _text(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _bytes(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
