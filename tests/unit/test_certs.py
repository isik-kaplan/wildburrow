import asyncio
import logging
import ssl
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from acme import challenges, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wildburrow.certs.acme import ACMEIssuer, IssueError, make_csr
from wildburrow.certs.manager import CertManager
from wildburrow.certs.store import CertStore
from wildburrow.core.names import Name

DOMAIN = "tunnel.example.com"
NOW = datetime(2026, 10, 14, tzinfo=UTC)


def self_signed(domains: Sequence[str], not_after: datetime) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


class FakeIssuer:
    def __init__(self, lifetime: timedelta = timedelta(days=90), fail: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.lifetime = lifetime
        self.fail = fail
        self.release = asyncio.Event()
        self.release.set()

    async def issue(self, domains: Sequence[str]) -> tuple[bytes, bytes]:
        self.calls.append(list(domains))
        await self.release.wait()
        if self.fail:
            self.fail -= 1
            raise RuntimeError("issuance failed")
        return self_signed(domains, NOW + self.lifetime)


class FakeDNS:
    def __init__(self) -> None:
        self.cnames: list[tuple[str, str]] = []

    async def ensure_cname(self, fqdn: str, target: str) -> None:
        self.cnames.append((fqdn, target))


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def manager(tmp_path: Path, issuer: FakeIssuer, manage: bool = False, clock: Clock | None = None) -> CertManager:
    return CertManager(
        DOMAIN, CertStore(tmp_path / "certs"), issuer, FakeDNS(), manage, timedelta(days=30), clock or Clock()
    )


def test_store_round_trip(tmp_path: Path) -> None:
    store = CertStore(tmp_path / "certs")
    assert store.parents() == []
    assert store.load("foo") is None
    key, chain = self_signed(["*.foo"], NOW + timedelta(days=5))
    stored = store.save("foo", key, chain)
    assert stored.expires == NOW + timedelta(days=5)
    assert store.load("foo") == stored
    assert stored.key.stat().st_mode & 0o777 == 0o600
    assert stored.key.parent.stat().st_mode & 0o777 == 0o700
    stored.key.unlink()
    assert store.load("foo") is None
    (tmp_path / "certs" / "file").write_text("")
    assert store.parents() == ["foo"]


def test_parent_of_names(tmp_path: Path) -> None:
    certs = manager(tmp_path, FakeIssuer())
    assert certs.parent(Name(("app",))) == DOMAIN
    assert certs.parent(Name(("api", "foo"))) == f"foo.{DOMAIN}"
    assert certs.parent(Name(("foo",), wildcard=True)) == f"foo.{DOMAIN}"
    assert certs.parent(Name(("bar", "foo"), wildcard=True)) == f"bar.foo.{DOMAIN}"


async def test_ensure_issues_once_and_dedupes(tmp_path: Path) -> None:
    issuer = FakeIssuer()
    issuer.release.clear()
    certs = manager(tmp_path, issuer, manage=True)
    waiting = [asyncio.create_task(certs.ensure(f"foo.{DOMAIN}")) for _ in range(3)]
    await asyncio.sleep(0)
    issuer.release.set()
    await asyncio.gather(*waiting)
    await certs.ensure(f"foo.{DOMAIN}")
    await certs.ensure(DOMAIN)
    assert issuer.calls == [[f"*.foo.{DOMAIN}"], [f"*.{DOMAIN}", DOMAIN]]
    assert certs._dns.cnames == [(f"*.foo.{DOMAIN}", DOMAIN)]


async def test_expired_certificates_are_reissued(tmp_path: Path) -> None:
    clock = Clock()
    issuer = FakeIssuer(lifetime=timedelta(days=1))
    certs = manager(tmp_path, issuer, clock=clock)
    await certs.ensure(f"foo.{DOMAIN}")
    assert certs.ready(f"foo.{DOMAIN}")
    clock.now += timedelta(days=2)
    assert not certs.ready(f"foo.{DOMAIN}")
    await certs.ensure(f"foo.{DOMAIN}")
    assert len(issuer.calls) == 2


async def test_context_lookup(tmp_path: Path) -> None:
    certs = manager(tmp_path, FakeIssuer())
    assert certs.context_for(f"x.foo.{DOMAIN}") is None
    await certs.ensure(f"foo.{DOMAIN}")
    await certs.ensure(DOMAIN)
    foo = certs.context_for(f"X.Foo.{DOMAIN}")
    assert isinstance(foo, ssl.SSLContext)
    assert certs.context_for(f"y.foo.{DOMAIN}") is foo
    assert certs.context_for(DOMAIN) is certs.context_for(f"app.{DOMAIN}") is not None
    assert certs.context_for(DOMAIN) is not foo
    for name in [None, "x.y.foo.tunnel.example.com", "example.org", f"bad_label.{DOMAIN}"]:
        assert certs.context_for(name) is None


async def test_sni_callback(tmp_path: Path) -> None:
    certs = manager(tmp_path, FakeIssuer())
    await certs.ensure(DOMAIN)
    sslobj = SimpleNamespace(context=None)
    assert certs.sni_callback(sslobj, "nope.example.org", None) == ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    assert sslobj.context is None
    assert certs.sni_callback(sslobj, f"app.{DOMAIN}", None) is None
    assert sslobj.context is certs.context_for(f"app.{DOMAIN}")


async def test_renewal_only_touches_due_certificates_in_use(tmp_path: Path, caplog) -> None:
    clock = Clock()
    issuer = FakeIssuer(lifetime=timedelta(days=40))
    certs = manager(tmp_path, issuer, clock=clock)
    for parent in [DOMAIN, f"used.{DOMAIN}", f"idle.{DOMAIN}"]:
        await certs.ensure(parent)
    issuer.calls.clear()

    await certs.renew_due([f"used.{DOMAIN}"])
    assert issuer.calls == []

    clock.now += timedelta(days=15)
    await certs.renew_due([f"used.{DOMAIN}"])
    assert sorted(call[0] for call in issuer.calls) == sorted([f"*.used.{DOMAIN}", f"*.{DOMAIN}"])

    clock.now += timedelta(days=50)
    issuer.fail = 3
    with caplog.at_level(logging.ERROR):
        await certs.renew_due([f"used.{DOMAIN}"])
    assert "renewing" in caplog.text


async def test_maintain_retries_the_base_certificate(tmp_path: Path, caplog) -> None:
    issuer = FakeIssuer(fail=1)
    certs = manager(tmp_path, issuer)
    renewed = asyncio.Event()

    def in_use() -> list[str]:
        renewed.set()
        return []

    task = asyncio.create_task(certs.maintain(in_use, interval=60, retry=0))
    await asyncio.wait_for(renewed.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(issuer.calls) == 2
    assert certs.ready(DOMAIN)
    assert "retrying" in caplog.text


def test_csr_lists_every_domain() -> None:
    key_pem, csr_pem = make_csr([f"*.{DOMAIN}", DOMAIN])
    csr = x509.load_pem_x509_csr(csr_pem)
    assert csr.is_signature_valid
    names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == [f"*.{DOMAIN}", DOMAIN]
    assert serialization.load_pem_private_key(key_pem, None).public_key() == csr.public_key()


async def test_issue_fails_without_a_dns_challenge(tmp_path: Path) -> None:
    class DNS:
        async def create_txt(self, fqdn: str, value: str) -> str:
            raise AssertionError("no record should be created")

    http_only = messages.ChallengeBody(chall=challenges.HTTP01(token=b"t" * 16), uri="https://x/c")
    authorization = SimpleNamespace(
        body=SimpleNamespace(
            status=messages.STATUS_PENDING,
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=DOMAIN),
            challenges=[http_only],
        )
    )
    order = SimpleNamespace(authorizations=[authorization])
    acme_client = SimpleNamespace(new_order=lambda csr: order)
    issuer = ACMEIssuer("https://acme.invalid/dir", "", tmp_path, DNS(), 0, 1)
    with pytest.raises(IssueError, match=f"no dns-01 challenge offered for {DOMAIN}"):
        await issuer._issue(acme_client, None, [DOMAIN])
