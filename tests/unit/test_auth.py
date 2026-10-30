import asyncio
import pwd
from pathlib import Path

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
# alice and a share the one test password; bob has his own.
USERS = f"alice:{HASH}\n# a comment\n\nbob:{PasswordHasher().hash('builder')}\na:{HASH}"


def public_key(comment: str | None = "laptop") -> asyncssh.SSHKey:
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    return key.convert_to_public()


def openssh_line(key: asyncssh.SSHKey) -> str:
    return key.export_public_key().decode().strip()


async def test_key_auth_matches_listed_keys() -> None:
    listed, unnamed, stranger = public_key(), public_key(None), public_key("stranger")
    auth = KeyAuth(KeySettings(f"# laptop\n\n  {openssh_line(listed)}  \n{openssh_line(unnamed)}\n"))
    assert await auth.authenticate(PublicKeyCredential("u", listed.public_data), PEER) == Identity(
        "laptop", "key", listed.get_fingerprint()
    )
    assert await auth.authenticate(PublicKeyCredential("u", unnamed.public_data), PEER) == Identity(
        unnamed.get_fingerprint(), "key", unnamed.get_fingerprint()
    )
    assert await auth.authenticate(PublicKeyCredential("u", stranger.public_data), PEER) is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("# only a comment", "authorized_keys: no keys found"),
        (
            "ssh-ed25519 not-base64-and-then-some-more-text",
            "authorized_keys: cannot parse 'ssh-ed25519 not-base64-and-then-some-mor': Invalid public key",
        ),
        (
            'command="x" ssh-ed25519 AAAA',
            "authorized_keys: cannot parse 'command=\"x\" ssh-ed25519 AAAA': Invalid public key",
        ),
    ],
)
def test_key_auth_config_errors(text: str, message: str) -> None:
    with pytest.raises(ConfigError) as error:
        KeyAuth(KeySettings(text))
    assert str(error.value) == message


async def test_key_auth_defaults_to_the_accounts_authorized_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".ssh").mkdir()
    listed = public_key()
    (tmp_path / ".ssh" / "authorized_keys").write_text(openssh_line(listed) + "\n")
    auth = KeyAuth(KeySettings())
    assert await auth.authenticate(PublicKeyCredential("u", listed.public_data), PEER) == Identity(
        "laptop", "key", listed.get_fingerprint()
    )
    (tmp_path / ".ssh" / "authorized_keys").write_text("")
    with pytest.raises(ConfigError, match=r"^authorized_keys: no keys found$"):
        KeyAuth(KeySettings())


def test_key_auth_without_keys_names_both_places(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(ConfigError) as error:
        KeyAuth(KeySettings())
    assert str(error.value) == (
        "authorized_keys: not set, and ~/.ssh/authorized_keys is unreadable: "
        f"[Errno 2] No such file or directory: '{tmp_path / '.ssh' / 'authorized_keys'}'"
    )


def test_key_auth_without_a_home(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_user(uid: int) -> None:
        raise KeyError(uid)

    monkeypatch.delenv("HOME")
    monkeypatch.setattr(pwd, "getpwuid", no_user)
    with pytest.raises(ConfigError) as error:
        KeyAuth(KeySettings())
    assert str(error.value) == (
        "authorized_keys: not set, and ~/.ssh/authorized_keys is unreadable: Could not determine home directory."
    )


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        (PasswordSettings("plain"), "users: expected 'name:argon2hash', got a line starting 'plain'"),
        (PasswordSettings(HASH), "users: expected 'name:argon2hash', got a line starting '$argon2id$v=19$m=655'"),
        (PasswordSettings(f":{HASH}"), "users: expected 'name:argon2hash', got a line starting ''"),
        (PasswordSettings(f"a b:{HASH}"), "users: expected 'name:argon2hash', got a line starting 'a b'"),
        (
            PasswordSettings(f"{'a' * 65}:{HASH}"),
            f"users: expected 'name:argon2hash', got a line starting '{'a' * 20}'",
        ),
        (
            PasswordSettings("alice:plain"),
            "users: alice's hash isn't an argon2 hash; make one with `wildburrow passwords hash alice`",
        ),
        (PasswordSettings(f"alice:{HASH}\nalice:{HASH}"), "users: alice is given twice"),
        (
            PasswordSettings(" \n# only a comment"),
            "users: none given; add a line for each with `wildburrow passwords hash NAME`",
        ),
        (PasswordSettings(USERS, max_failures=0), "max_failures and block_seconds must be at least 1"),
        (PasswordSettings(USERS, block_seconds=0), "max_failures and block_seconds must be at least 1"),
    ],
)
def test_password_config_errors(settings: PasswordSettings, message: str) -> None:
    with pytest.raises(ConfigError) as error:
        PasswordAuth(settings)
    assert str(error.value) == message


def test_password_limits_of_one_are_allowed() -> None:
    PasswordAuth(PasswordSettings(f"{'a' * 64}:{HASH}", max_failures=1, block_seconds=1))


async def test_password_accepts_the_right_password() -> None:
    auth = PasswordAuth(PasswordSettings(USERS))
    alice = Identity("alice", "password", "alice")
    assert await auth.authenticate(PasswordCredential("alice", "secret"), PEER) == alice
    assert await auth.authenticate(PasswordCredential("bob", "builder"), PEER) == Identity("bob", "password", "bob")
    assert await auth.authenticate(PasswordCredential("alice", "Secret"), PEER) is None


@pytest.mark.parametrize(
    ("username", "password"),
    [("bob", "secret"), ("alice", "builder"), ("mallory", "secret"), ("mallory", ""), ("Alice", "secret")],
)
async def test_a_password_logs_in_only_its_own_user(username: str, password: str) -> None:
    auth = PasswordAuth(PasswordSettings(USERS, max_failures=1))
    assert await auth.authenticate(PasswordCredential(username, password), PEER) is None
    # A name no one has counts as a failure, as a wrong password does.
    assert auth.blocked(PEER.host)


async def test_password_blocks_an_address_after_repeated_failures() -> None:
    clock = Clock()
    auth = PasswordAuth(PasswordSettings(USERS, max_failures=2, block_seconds=60), clock=clock)
    for _ in range(2):
        assert await auth.authenticate(PasswordCredential("a", "wrong"), PEER) is None
    assert auth.blocked(PEER.host)
    assert await auth.authenticate(PasswordCredential("a", "secret"), PEER) is None
    assert await auth.authenticate(PasswordCredential("a", "secret"), OTHER_PEER) is not None

    clock.now += 60
    assert not auth.blocked(PEER.host)
    assert await auth.authenticate(PasswordCredential("a", "secret"), PEER) is not None


async def test_password_counts_in_flight_attempts() -> None:
    auth = PasswordAuth(PasswordSettings(USERS, max_failures=3))
    results = await asyncio.gather(*(auth.authenticate(PasswordCredential("a", "wrong"), PEER) for _ in range(10)))
    assert results == [None] * 10
    assert len(auth._failures[PEER.host]) == 3


async def test_success_does_not_count_as_failure() -> None:
    auth = PasswordAuth(PasswordSettings(USERS, max_failures=1))
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
    keys = Fixed((PublicKeyCredential,), Identity("k", "key", "k"))
    second = Fixed((PasswordCredential,), Identity("p", "password", "p"))
    authenticator = Authenticator([first, keys, second])
    assert authenticator.accepts(PasswordCredential)
    assert await authenticator.authenticate(PasswordCredential("u", "x"), PEER) == Identity("p", "password", "p")
    assert (first.calls, keys.calls, second.calls) == (1, 0, 1)


async def test_authenticator_without_a_matching_provider() -> None:
    authenticator = Authenticator([Fixed((PasswordCredential,), Identity("p", "password", "p"))])
    assert not authenticator.accepts(PublicKeyCredential)
    assert await authenticator.authenticate(PublicKeyCredential("u", b"k"), PEER) is None


def test_password_is_hidden_from_repr() -> None:
    assert "secret" not in repr(PasswordCredential("u", "secret"))
