import base64
import hashlib
import struct
import subprocess
from pathlib import Path

import asyncssh
import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow.auth import sshsig
from wildburrow.auth.keys import KeyAuth, KeySettings
from wildburrow.core.types import Identity, Peer, SignedChallengeCredential

MESSAGE = b"wildburrow-login:tunnel.example.com:nonce"


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, bytes, bytes]:
    root = tmp_path_factory.mktemp("sshsig")
    for name in ("signer", "other"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", root / name], check=True)
    public = asyncssh.read_public_key(root / "signer.pub").public_data
    other = asyncssh.read_public_key(root / "other.pub").public_data
    return root / "signer", public, other


def sign(key: Path, message: bytes = MESSAGE, namespace: str = "wildburrow") -> str:
    result = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", namespace],
        input=message,
        capture_output=True,
        check=True,
    )
    return result.stdout.decode()


def armor(blob: bytes) -> str:
    return f"{sshsig.ARMOR_BEGIN}\n{base64.b64encode(blob).decode()}\n{sshsig.ARMOR_END}\n"


def unarmor(armored: str) -> bytes:
    return base64.b64decode("".join(armored.strip().splitlines()[1:-1]))


def string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def test_valid_signature(keys) -> None:
    key, public, _ = keys
    sshsig.verify(sign(key), public, "wildburrow", MESSAGE)


def test_sha256_signatures_are_accepted_too(keys) -> None:
    key, public, _ = keys
    blob = unarmor(sign(key))
    reader = sshsig._Reader(blob)
    reader.take(6), reader.uint32()
    signer, namespace, reserved, _, _ = (reader.string() for _ in range(5))

    signed = (
        b"SSHSIG" + string(namespace) + string(reserved) + string(b"sha256") + string(hashlib.sha256(MESSAGE).digest())
    )
    raw_key = asyncssh.read_private_key(key)
    resigned = raw_key.sign(signed, raw_key.algorithm)
    rebuilt = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + b"".join(string(part) for part in (signer, namespace, reserved, b"sha256", resigned))
    )
    sshsig.verify(armor(rebuilt), public, "wildburrow", MESSAGE)


def with_parts(blob: bytes, **changes: bytes) -> bytes:
    reader = sshsig._Reader(blob)
    reader.take(6), reader.uint32()
    parts = {part: reader.string() for part in ("signer", "namespace", "reserved", "hash", "signature")}
    return blob[:10] + b"".join(string(part) for part in (parts | changes).values())


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda s, b: "garbage", "not an armored SSH signature"),
        (lambda s, b: s.strip().removesuffix(sshsig.ARMOR_END), "not an armored SSH signature"),
        (lambda s, b: s.strip().removeprefix(sshsig.ARMOR_BEGIN), "not an armored SSH signature"),
        (lambda s, b: armor(b)[:-35] + "!!!!\n" + sshsig.ARMOR_END, "signature is not valid base64"),
        (lambda s, b: s.replace("\n", "\n*", 1), "signature is not valid base64"),
        (lambda s, b: armor(b"XXXXXX" + b[6:]), "unsupported signature format"),
        (lambda s, b: armor(b[:6] + struct.pack(">I", 2) + b[10:]), "unsupported signature format"),
        (lambda s, b: armor(b[:40]), "truncated signature"),
        (lambda s, b: armor(b[:-1]), "truncated signature"),
        (lambda s, b: armor(b[:10] + struct.pack(">I", 0xFFFFFFFF) + b[14:]), "truncated signature"),
        (lambda s, b: armor(b + b"extra"), "trailing data after the signature"),
        (lambda s, b: armor(with_parts(b, hash=b"md5")), "unsupported hash 'md5'"),
        (lambda s, b: armor(with_parts(b, hash=b"\xff")), "unsupported hash '\ufffd'"),
    ],
)
def test_malformed_signatures(keys, mutate, reason: str) -> None:
    key, public, _ = keys
    armored = sign(key)
    with pytest.raises(sshsig.InvalidSignature) as error:
        sshsig.verify(mutate(armored, unarmor(armored)), public, "wildburrow", MESSAGE)
    assert str(error.value) == reason


@pytest.mark.parametrize(
    ("signer", "namespace", "message", "reason"),
    [
        ("other", "wildburrow", MESSAGE, "signed with a different key"),
        ("signer", "git", MESSAGE, "signed for a different namespace"),
        ("signer", "wildburrow", MESSAGE + b"x", "signature does not match"),
    ],
)
def test_wrong_key_namespace_and_message(keys, signer: str, namespace: str, message: bytes, reason: str) -> None:
    key, public, _ = keys
    with pytest.raises(sshsig.InvalidSignature) as error:
        sshsig.verify(sign(key, namespace=namespace), public if signer == "signer" else keys[2], "wildburrow", message)
    assert str(error.value) == reason


@given(st.binary(max_size=400))
def test_random_blobs_never_crash(blob: bytes) -> None:
    try:
        sshsig.verify(armor(blob), b"key", "wildburrow", MESSAGE)
    except sshsig.InvalidSignature:
        return
    pytest.fail("a random blob verified")


async def test_key_auth_checks_signed_challenges(keys) -> None:
    key, public, other = keys
    line = (key.parent / "signer.pub").read_text()
    auth = KeyAuth(KeySettings(line))
    peer = Peer("192.0.2.1", 1)
    good = SignedChallengeCredential(public, MESSAGE, sign(key))
    fingerprint = asyncssh.import_public_key(line).get_fingerprint()
    assert await auth.authenticate(good, peer) == Identity("signer", "key", fingerprint)
    replayed = SignedChallengeCredential(public, MESSAGE + b"other-nonce", sign(key))
    assert await auth.authenticate(replayed, peer) is None
    stranger = SignedChallengeCredential(other, MESSAGE, sign(key.parent / "other"))
    assert await auth.authenticate(stranger, peer) is None
