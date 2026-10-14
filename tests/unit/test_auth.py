import asyncio

import asyncssh
import pytest
from argon2 import PasswordHasher

from wildburrow.auth.base import Authenticator
from wildburrow.auth.keys import KeyAuth, KeySettings
from wildburrow.auth.password import PasswordAuth, PasswordSettings
from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, PasswordCredential, Peer, PublicKeyCredential

PEER = Peer("192.0.2.1", 50000)
OTHER_PEER = Peer("192.0.2.2", 50000)
HASH = PasswordHasher().hash("secret")


def public_key(comment: str | None = "laptop") -> asyncssh.SSHKey:
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    return key.convert_to_public()


def openssh_line(key: asyncssh.SSHKey) -> str:
    return key.export_public_key().decode().strip()


async def test_key_auth_matches_listed_keys() -> None:
    listed, unnamed, stranger = public_key(), public_key(None), public_key("stranger")
    auth = KeyAuth(KeySettings(f"# laptop\n\n  {openssh_line(listed)}  \n{openssh_line(unnamed)}\n"))
    assert await auth.authenticate(PublicKeyCredential("u", listed.public_data), PEER) == Identity("laptop", "key")
    assert await auth.authenticate(PublicKeyCredential("u", unnamed.public_data), PEER) == Identity(
        unnamed.get_fingerprint(), "key"
    )
    assert await auth.authenticate(PublicKeyCredential("u", stranger.public_data), PEER) is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "no keys found"),
        ("# only a comment", "no keys found"),
        ("ssh-ed25519 not-base64", "cannot parse"),
        ('command="x" ssh-ed25519 AAAA', "cannot parse"),
    ],
)
def test_key_auth_config_errors(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        KeyAuth(KeySettings(text))


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        (PasswordSettings("plain"), "not an argon2 hash"),
        (PasswordSettings(HASH, max_failures=0), "at least 1"),
        (PasswordSettings(HASH, block_seconds=0), "at least 1"),
    ],
)
def test_password_config_errors(settings: PasswordSettings, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        PasswordAuth(settings)


async def test_password_accepts_the_right_password() -> None:
    auth = PasswordAuth(PasswordSettings(HASH))
    assert await auth.authenticate(PasswordCredential("alice", "secret"), PEER) == Identity("alice", "password")
    assert await auth.authenticate(PasswordCredential("alice", "Secret"), PEER) is None


async def test_password_blocks_an_address_after_repeated_failures() -> None:
    clock = Clock()
    auth = PasswordAuth(PasswordSettings(HASH, max_failures=2, block_seconds=60), clock=clock)
    for _ in range(2):
        assert await auth.authenticate(PasswordCredential("a", "wrong"), PEER) is None
    assert auth.blocked(PEER.host)
    assert await auth.authenticate(PasswordCredential("a", "secret"), PEER) is None
    assert await auth.authenticate(PasswordCredential("a", "secret"), OTHER_PEER) is not None

    clock.now += 60
    assert not auth.blocked(PEER.host)
    assert await auth.authenticate(PasswordCredential("a", "secret"), PEER) is not None


async def test_password_counts_in_flight_attempts() -> None:
    auth = PasswordAuth(PasswordSettings(HASH, max_failures=3))
    results = await asyncio.gather(*(auth.authenticate(PasswordCredential("a", "wrong"), PEER) for _ in range(10)))
    assert results == [None] * 10
    assert len(auth._failures[PEER.host]) == 3


async def test_success_does_not_count_as_failure() -> None:
    auth = PasswordAuth(PasswordSettings(HASH, max_failures=1))
    for _ in range(3):
        assert await auth.authenticate(PasswordCredential("a", "secret"), PEER) is not None


class Fixed:
    def __init__(self, handles: tuple[type, ...], identity: Identity | None) -> None:
        self.handles = handles
        self.identity = identity
        self.calls = 0

    async def authenticate(self, credential, peer):
        self.calls += 1
        return self.identity


async def test_authenticator_tries_matching_providers_in_order() -> None:
    first = Fixed((PasswordCredential,), None)
    keys = Fixed((PublicKeyCredential,), Identity("k", "key"))
    second = Fixed((PasswordCredential,), Identity("p", "password"))
    authenticator = Authenticator([first, keys, second])
    assert authenticator.accepts(PasswordCredential)
    assert await authenticator.authenticate(PasswordCredential("u", "x"), PEER) == Identity("p", "password")
    assert (first.calls, keys.calls, second.calls) == (1, 0, 1)


async def test_authenticator_without_a_matching_provider() -> None:
    authenticator = Authenticator([Fixed((PasswordCredential,), Identity("p", "password"))])
    assert not authenticator.accepts(PublicKeyCredential)
    assert await authenticator.authenticate(PublicKeyCredential("u", b"k"), PEER) is None


def test_password_is_hidden_from_repr() -> None:
    assert "secret" not in repr(PasswordCredential("u", "secret"))
