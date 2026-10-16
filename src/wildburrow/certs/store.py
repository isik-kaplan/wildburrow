import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509

CHAIN = "chain.pem"
KEY = "key.pem"
PARTIAL = ".partial"


@dataclass(frozen=True, slots=True)
class StoredCert:
    chain: Path
    key: Path
    expires: datetime


def _write(path: Path, data: bytes, mode: int) -> None:
    partial = path.with_suffix(PARTIAL)
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
    partial.replace(path)


class CertStore:
    """Certificates keyed by the parent domain their wildcard covers: `foo.example.com` holds `*.foo.example.com`."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def save(self, parent: str, key_pem: bytes, chain_pem: bytes) -> StoredCert:
        directory = self._root / parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write(directory / KEY, key_pem, 0o600)
        _write(directory / CHAIN, chain_pem, 0o644)
        return self._read(directory)

    def load(self, parent: str) -> StoredCert | None:
        directory = self._root / parent
        if not (directory / CHAIN).exists() or not (directory / KEY).exists():
            return None
        return self._read(directory)

    def parents(self) -> list[str]:
        if not self._root.exists():
            return []
        return sorted(path.name for path in self._root.iterdir() if path.is_dir())

    @staticmethod
    def _read(directory: Path) -> StoredCert:
        chain = directory / CHAIN
        leaf = x509.load_pem_x509_certificates(chain.read_bytes())[0]
        return StoredCert(chain, directory / KEY, leaf.not_valid_after_utc)
