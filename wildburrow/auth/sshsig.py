import hashlib

from asyncssh.public_key import decode_ssh_public_key

from wildburrow import tokens

MAGIC = b"SSHSIG"
VERSION = 1
HASHES = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}


class InvalidSignature(Exception):
    pass


def _string(value: bytes) -> bytes:
    return len(value).to_bytes(4) + value


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def take(self, size: int) -> bytes:
        if self._offset + size > len(self._data):
            raise InvalidSignature("truncated signature")
        chunk = self._data[self._offset : self._offset + size]
        self._offset += size
        return chunk

    def uint32(self) -> int:
        return int.from_bytes(self.take(4))

    def string(self) -> bytes:
        return self.take(self.uint32())

    def done(self) -> bool:
        return self._offset == len(self._data)


def signer(blob: bytes) -> bytes:
    """The public key a signature claims to be from; only `verify` says whether it is."""
    reader = _Reader(blob)
    if reader.take(len(MAGIC)) != MAGIC or reader.uint32() != VERSION:
        raise InvalidSignature("unsupported signature format")
    return reader.string()


def verify(armored: str, public_key: bytes, namespace: str, message: bytes) -> None:
    try:
        reader = _Reader(tokens.unarmor(armored))
    except ValueError as exc:
        raise InvalidSignature(str(exc)) from None
    if reader.take(len(MAGIC)) != MAGIC or reader.uint32() != VERSION:
        raise InvalidSignature("unsupported signature format")
    signer, signed_namespace, reserved = reader.string(), reader.string(), reader.string()
    hash_name, signature = reader.string().decode(errors="replace"), reader.string()
    if not reader.done():
        raise InvalidSignature("trailing data after the signature")
    if signer != public_key:
        raise InvalidSignature("signed with a different key")
    if signed_namespace != namespace.encode():
        raise InvalidSignature("signed for a different namespace")
    if hash_name not in HASHES:
        raise InvalidSignature(f"unsupported hash {hash_name!r}")
    signed = MAGIC + b"".join(
        _string(part) for part in (signed_namespace, reserved, hash_name.encode(), HASHES[hash_name](message).digest())
    )
    if not decode_ssh_public_key(public_key).verify(signed, signature):
        raise InvalidSignature("signature does not match")
