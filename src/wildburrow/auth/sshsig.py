import base64
import hashlib
import struct

from asyncssh.public_key import decode_ssh_public_key

MAGIC = b"SSHSIG"
VERSION = 1
ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"
HASHES = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}


class InvalidSignature(Exception):
    pass


def _string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


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
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.uint32())

    def done(self) -> bool:
        return self._offset == len(self._data)


def verify(armored: str, public_key: bytes, namespace: str, message: bytes) -> None:
    body = armored.strip()
    if not body.startswith(ARMOR_BEGIN) or not body.endswith(ARMOR_END):
        raise InvalidSignature("not an armored SSH signature")
    try:
        blob = base64.b64decode("".join(body[len(ARMOR_BEGIN) : -len(ARMOR_END)].split()), validate=True)
    except ValueError:
        raise InvalidSignature("signature is not valid base64") from None
    reader = _Reader(blob)
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
