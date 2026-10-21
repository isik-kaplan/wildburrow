import time
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import Credentials
from wildburrow import protocol, tokens
from wildburrow.auth.token import SKEW_SECONDS, TokenAuth, TokenSettings
from wildburrow.client.websocket import sign
from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, Peer, TokenCredential
from wildburrow.tokens import HASHED_PREFIX as PREFIX
from wildburrow.tokens import Grant, digest, new_token

PEER = Peer("192.0.2.1", 1)


def test_new_tokens_are_unique_and_prefixed() -> None:
    tokens = {new_token() for _ in range(100)}
    assert {len(token) for token in tokens} == {len(PREFIX) + 43}
    assert len(tokens) == 100
    assert all(token.startswith(PREFIX) and len(token) > 40 for token in tokens)


async def test_tokens_match_by_hash() -> None:
    token = new_token()
    auth = TokenAuth(TokenSettings(f"# ci\n\nname:with:colons:{digest(token)}\n"))
    assert await auth.authenticate(TokenCredential(token), PEER) == Identity("name:with:colons", "token", digest(token))
    assert await auth.authenticate(TokenCredential(token + "x"), PEER) is None
    assert await auth.authenticate(TokenCredential(digest(token)), PEER) is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "set hashes, signers, or both"),
        ("# only comments", "set hashes, signers, or both"),
        ("nocolon", "hashes: expected 'name:sha256hex', got 'nocolon'"),
        (f":{'a' * 64}", f"hashes: expected 'name:sha256hex', got ':{'a' * 39}'"),
        ("name:abc", "hashes: expected 'name:sha256hex', got 'name:abc'"),
        (f"name:{'A' * 64}", f"hashes: expected 'name:sha256hex', got 'name:{'A' * 35}'"),
        (f"name:{'X' * 64}", f"hashes: expected 'name:sha256hex', got 'name:{'X' * 35}'"),
    ],
)
def test_config_errors(text: str, message: str) -> None:
    with pytest.raises(ConfigError) as error:
        TokenAuth(TokenSettings(text))
    assert str(error.value) == message


def test_token_is_hidden_from_repr() -> None:
    assert "secret" not in repr(TokenCredential("secret"))


NOW = 1_800_000_000


def mint(grant: Grant, key: Path, namespace: str = tokens.NAMESPACE) -> str:
    return tokens.encode(grant.payload(), tokens.unarmor(sign(key, namespace, grant.payload())))


def signed_auth(credentials: Credentials, now: float = NOW, **settings: Any) -> TokenAuth:
    return TokenAuth(TokenSettings(signers=f"# me\n{credentials.public_key}", **settings), clock=lambda: now)


GRANT = Grant("alice", ("alice", "*.alice"), NOW + 3600, NOW, "0123456789abcdef")


async def test_a_signed_token_logs_in_as_its_name_with_its_names(credentials: Credentials) -> None:
    identity = await signed_auth(credentials).authenticate(TokenCredential(mint(GRANT, credentials.key)), PEER)
    assert identity == Identity("alice", "token", "signed:alice")
    assert identity is not None
    assert identity.names == ("alice", "*.alice")


async def test_a_token_that_never_expires_stays_good(credentials: Credentials) -> None:
    grant = GRANT.__replace__(expires=None, names=None)
    auth = signed_auth(credentials, now=NOW * 10)
    identity = await auth.authenticate(TokenCredential(mint(grant, credentials.key)), PEER)
    assert identity is not None
    assert identity.names is None


@pytest.mark.parametrize(
    ("now", "accepted"),
    [(NOW + 3600, True), (NOW + 3600 + SKEW_SECONDS, True), (NOW + 3600 + SKEW_SECONDS + 1, False)],
)
async def test_an_expired_token_is_refused_past_the_clock_skew(
    credentials: Credentials, now: float, accepted: bool
) -> None:
    identity = await signed_auth(credentials, now=now).authenticate(TokenCredential(mint(GRANT, credentials.key)), PEER)
    assert (identity is not None) is accepted


async def test_tokens_from_anyone_but_a_signer_are_refused(credentials: Credentials) -> None:
    auth = signed_auth(credentials)
    token = mint(GRANT, credentials.key)
    payload, signature = token.removeprefix(tokens.PREFIX).split(".")
    tampered = tokens.encode(GRANT.__replace__(names=None).payload(), tokens.decode(token)[2])
    for refused in [
        mint(GRANT, credentials.other_key),
        mint(GRANT, credentials.key, namespace=protocol.SIGNATURE_NAMESPACE),
        tampered,
        f"{tokens.PREFIX}{payload}.{signature[:-8]}",
        f"{tokens.PREFIX}{payload}",
        tokens.PREFIX + "garbage",
    ]:
        assert await auth.authenticate(TokenCredential(refused), PEER) is None


async def test_a_denied_token_is_refused(credentials: Credentials) -> None:
    auth = signed_auth(credentials, deny=("ffff", GRANT.id))
    assert await auth.authenticate(TokenCredential(mint(GRANT, credentials.key)), PEER) is None
    other = GRANT.__replace__(id="1111111111111111")
    assert await auth.authenticate(TokenCredential(mint(other, credentials.key)), PEER) is not None


async def test_signed_and_hashed_tokens_work_side_by_side(credentials: Credentials) -> None:
    hashed = new_token()
    auth = signed_auth(credentials, hashes=f"bob:{digest(hashed)}")
    assert await auth.authenticate(TokenCredential(hashed), PEER) == Identity("bob", "token", digest(hashed))
    assert await auth.authenticate(TokenCredential(mint(GRANT, credentials.key)), PEER) is not None


async def test_a_hashed_only_server_refuses_signed_tokens(credentials: Credentials) -> None:
    auth = TokenAuth(TokenSettings(hashes=f"bob:{digest(new_token())}"))
    assert await auth.authenticate(TokenCredential(mint(GRANT, credentials.key)), PEER) is None


@pytest.mark.parametrize(
    ("signers", "message"),
    [
        ("not a key", "signers: cannot read the key 'not a key'"),
        ("ssh-ed25519 AAAA" + "x" * 60, "signers: cannot read the key 'ssh-ed25519 AAAAxxxxxxxxxxxxxxxxxxxxxxxx'"),
    ],
)
def test_signers_must_be_keys(signers: str, message: str) -> None:
    with pytest.raises(ConfigError) as error:
        TokenAuth(TokenSettings(signers=signers))
    assert str(error.value) == message


def test_the_real_clock_is_the_default(credentials: Credentials) -> None:
    assert TokenAuth(TokenSettings(signers=credentials.public_key))._clock is time.time
