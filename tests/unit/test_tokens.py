import base64
import contextlib
import hashlib
import json
import re
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow import tokens
from wildburrow.tokens import Grant

GRANT = Grant("alice", ("alice", "*.alice"), 1_900_000_000, 1_800_000_000, "0123456789abcdef")


def test_a_payload_is_compact_sorted_json() -> None:
    assert GRANT.payload() == (
        b'{"expires":1900000000,"id":"0123456789abcdef","issued":1800000000,"name":"alice","names":["alice","*.alice"]}'
    )
    assert json.loads(GRANT.__replace__(names=None, expires=None).payload())["names"] is None


def test_a_token_carries_the_signed_bytes_and_the_signature() -> None:
    token = tokens.encode(GRANT.payload(), b"\xffsignature")
    assert token.startswith(tokens.PREFIX)
    assert "=" not in token
    assert tokens.decode(token) == (GRANT, GRANT.payload(), b"\xffsignature")
    never = GRANT.__replace__(names=None, expires=None)
    assert tokens.decode(tokens.encode(never.payload(), b"s"))[0] == never


def encoded(**changes: Any) -> str:
    fields = json.loads(GRANT.payload()) | changes
    payload = json.dumps(fields).encode()
    return tokens.encode(payload, b"s")


@pytest.mark.parametrize(
    ("token", "message"),
    [
        ("wb_random", "not a signed token"),
        (tokens.PREFIX + "e30.c2ln.c2ln", "not a signed token"),
        (tokens.PREFIX + "e30", "not a signed token"),
        (tokens.PREFIX + "!!!.c2ln", "Only base64 data is allowed"),
        (tokens.PREFIX + base64.urlsafe_b64encode(b"not json").decode() + ".c2ln", "Expecting value"),
        (tokens.encode(b"[]", b"s"), "not a grant"),
        (encoded(name=""), "expected str, got ''"),
        (encoded(name=7), "expected str, got 7"),
        (encoded(names="alice"), "names must be a list of names"),
        (encoded(names=["alice", 7]), "names must be a list of names"),
        (encoded(expires="soon"), "expected int, got 'soon'"),
        (encoded(expires=True), "expected int, got True"),
        (encoded(issued=None), "expected int, got None"),
        (encoded(issued=1.5), "expected int, got 1.5"),
        (encoded(id=""), "expected str, got ''"),
        (encoded(id=None), "expected str, got None"),
    ],
)
def test_anything_but_a_grant_is_refused(token: str, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(message)}"):
        tokens.decode(token)


def test_a_grant_nested_too_deep_is_refused() -> None:
    # Whether the parser runs out of input or of stack first depends on how deep the stack already is.
    with pytest.raises(ValueError, match=r"^(Expecting value|not a grant)"):
        tokens.decode(tokens.encode(b"[" * 100_000, b"s"))


def test_every_field_is_needed() -> None:
    for field in json.loads(GRANT.payload()):
        fields = json.loads(GRANT.payload())
        del fields[field]
        with pytest.raises(ValueError, match=r"^not a grant$"):
            tokens.decode(tokens.encode(json.dumps(fields).encode(), b"s"))


@given(st.text())
def test_decoding_any_text_only_ever_refuses(text: str) -> None:
    with contextlib.suppress(ValueError):
        tokens.decode(tokens.PREFIX + text)


def test_hashed_tokens_are_random_and_known_by_their_digest() -> None:
    minted = {tokens.new_token() for _ in range(50)}
    assert len(minted) == 50
    assert all(token.startswith(tokens.HASHED_PREFIX) and len(token) == 46 for token in minted)
    assert tokens.digest("wb_x") == hashlib.sha256(b"wb_x").hexdigest()


def test_ids_are_random_hex() -> None:
    ids = {tokens.new_id() for _ in range(50)}
    assert len(ids) == 50
    assert all(len(found) == 16 and int(found, 16) >= 0 for found in ids)


def test_encoding_keeps_every_character_but_padding() -> None:
    # Bytes whose encoding ends in a letter that stripping too much would also take.
    signature = b"\x00\x00\x17"
    assert tokens.encode(b"a", signature).endswith(".AAAX")
    assert tokens.decode(tokens.encode(GRANT.payload(), signature))[2] == signature
    assert tokens.encode(b"a", b"ab") == f"{tokens.PREFIX}YQ.YWI"


def test_armor_round_trips() -> None:
    assert tokens.unarmor(tokens.armor(b"\x00signature\xff")) == b"\x00signature\xff"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("no armor at all", "not an armored SSH signature"),
        (f"{tokens.ARMOR_BEGIN}\n!!!!\n{tokens.ARMOR_END}", "signature is not valid base64"),
    ],
)
def test_unarmor_refuses(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        tokens.unarmor(text)
