import pytest

from wildburrow.auth.token import PREFIX, TokenAuth, TokenSettings, digest, new_token
from wildburrow.config import ConfigError
from wildburrow.core.types import Identity, Peer, TokenCredential

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
        ("", "hashes: no tokens found"),
        ("# only comments", "hashes: no tokens found"),
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
