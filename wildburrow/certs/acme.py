import asyncio
import hashlib
import logging
import os
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

import josepy
from acme import challenges, client, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from wildburrow.dns.base import DNSError, DNSProvider

log = logging.getLogger(__name__)

USER_AGENT = "wildburrow"


class IssueError(Exception):
    pass


class Issuer(Protocol):
    async def issue(self, domains: Sequence[str]) -> tuple[bytes, bytes]: ...


def _private_key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    encoding, private_format = serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8
    return key.private_bytes(encoding, private_format, serialization.NoEncryption())


def make_csr(domains: Sequence[str]) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    san = x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains])
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    # ACME servers take only the names from a CSR and set the certificate's extensions themselves.
    builder = builder.add_extension(san, critical=False)  # pragma: no mutate
    csr = builder.sign(key, hashes.SHA256())
    return _private_key_pem(key), csr.public_bytes(serialization.Encoding.PEM)


class ACMEIssuer:
    def __init__(
        self, directory: str, email: str, state_dir: Path, dns: DNSProvider, propagation: float, timeout: float
    ) -> None:
        self._directory = directory
        self._email = email
        self._state_dir = state_dir / hashlib.sha256(directory.encode()).hexdigest()[:16]
        self._dns = dns
        self._propagation = propagation
        self._timeout = timeout
        self._lock = asyncio.Lock()
        self._client: client.ClientV2 | None = None
        self._jwk: josepy.JWKEC | None = None

    def _account_key(self) -> josepy.JWKEC:
        path = self._state_dir / "account.key"
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(_private_key_pem(key))
        return josepy.JWKEC(key=key)

    def _connect(self) -> tuple[client.ClientV2, josepy.JWKEC]:
        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        jwk = self._account_key()
        net = client.ClientNetwork(jwk, alg=josepy.ES256, user_agent=USER_AGENT)
        acme = client.ClientV2(client.ClientV2.get_directory(self._directory, net), net)
        account = self._state_dir / "account.json"
        if account.exists():
            net.account = messages.RegistrationResource.json_loads(account.read_text())
        else:
            registration = messages.NewRegistration.from_data(email=self._email or None, terms_of_service_agreed=True)
            account.write_text(acme.new_account(registration).json_dumps())
        return acme, jwk

    async def issue(self, domains: Sequence[str]) -> tuple[bytes, bytes]:
        async with self._lock:
            if self._client is None:
                self._client, self._jwk = await asyncio.to_thread(self._connect)
            return await self._issue(self._client, self._jwk, domains)  # type: ignore[arg-type]

    async def _issue(self, acme: client.ClientV2, jwk: josepy.JWKEC, domains: Sequence[str]) -> tuple[bytes, bytes]:
        key_pem, csr_pem = make_csr(domains)
        order = await asyncio.to_thread(acme.new_order, csr_pem)
        records: list[object] = []
        try:
            pending = []
            for authorization in order.authorizations:
                if authorization.body.status == messages.STATUS_VALID:
                    continue
                challenge = next(
                    (c for c in authorization.body.challenges if isinstance(c.chall, challenges.DNS01)), None
                )
                if challenge is None:
                    raise IssueError(f"no dns-01 challenge offered for {authorization.body.identifier.value}")
                name = challenge.chall.validation_domain_name(authorization.body.identifier.value)
                records.append(await self._dns.create_txt(name, challenge.chall.validation(jwk)))
                pending.append(challenge)
            await asyncio.sleep(self._propagation)
            for challenge in pending:
                await asyncio.to_thread(acme.answer_challenge, challenge, challenge.chall.response(jwk))
            deadline = datetime.now() + timedelta(seconds=self._timeout)
            order = await asyncio.to_thread(acme.poll_and_finalize, order, deadline)
        finally:
            for record in records:
                try:
                    await self._dns.delete_txt(record)
                except DNSError as exc:
                    log.warning("could not remove a challenge record: %s", exc)
        return key_pem, order.fullchain_pem.encode()
