import asyncio
import contextlib
import hashlib
import logging
import re
import ssl
import stat
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import josepy
import pytest
from acme import challenges, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests.unit.test_registry import FakeTunnel
from wildburrow.auth.base import Authenticator
from wildburrow.certs import acme as acme_module
from wildburrow.certs.acme import ACMEIssuer, IssueError, make_csr
from wildburrow.certs.manager import CertManager
from wildburrow.certs.store import CertStore
from wildburrow.core.context import CertificateFailed, ServerContext
from wildburrow.core.names import Name
from wildburrow.core.types import Identity
from wildburrow.dns.base import DNSError

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


JWK = josepy.JWKEC(key=ec.generate_private_key(ec.SECP256R1()))
DIRECTORY = "https://acme.invalid/dir"


def authorization(domain: str, status: messages.Status = messages.STATUS_PENDING) -> SimpleNamespace:
    dns01 = messages.ChallengeBody(chall=challenges.DNS01(token=b"t" * 16), uri="https://x/c")
    identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain)
    return SimpleNamespace(body=SimpleNamespace(status=status, identifier=identifier, challenges=[dns01]))


class RecordingDNS:
    def __init__(self, failure: Exception | None = None) -> None:
        self.created: list[str] = []
        self.deleted: list[object] = []
        self.failure = failure

    async def create_txt(self, fqdn: str, value: str) -> str:
        self.created.append(fqdn)
        return f"record-{len(self.created)}"

    async def delete_txt(self, record: object) -> None:
        if self.failure is not None:
            raise self.failure
        self.deleted.append(record)


class FakeACME:
    def __init__(self, *authorizations: SimpleNamespace) -> None:
        self.order = SimpleNamespace(authorizations=list(authorizations))
        self.answered: list[object] = []
        self.deadline: datetime | None = None

    def new_order(self, csr_pem: bytes) -> SimpleNamespace:
        return self.order

    def answer_challenge(self, challenge: object, response: object) -> None:
        self.answered.append(challenge)

    def poll_and_finalize(self, order: object, deadline: datetime) -> SimpleNamespace:
        self.deadline = deadline
        return SimpleNamespace(fullchain_pem="chain")


async def test_issue_answers_every_pending_authorization_and_cleans_up(tmp_path: Path) -> None:
    valid, first, second = authorization("a.example.com", messages.STATUS_VALID), *map(authorization, "bc")
    acme_client = FakeACME(valid, first, second)
    dns = RecordingDNS()
    issuer = ACMEIssuer(DIRECTORY, "", tmp_path, dns, 0, 90)
    started = datetime.now()
    assert (await issuer._issue(acme_client, JWK, ["b", "c"]))[1] == b"chain"
    assert dns.created == ["_acme-challenge.b", "_acme-challenge.c"]
    assert dns.deleted == ["record-1", "record-2"]
    assert acme_client.answered == [first.body.challenges[0], second.body.challenges[0]]
    assert started + timedelta(seconds=90) <= acme_client.deadline <= datetime.now() + timedelta(seconds=90)


async def test_a_challenge_record_that_will_not_go_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    issuer = ACMEIssuer(DIRECTORY, "", tmp_path, RecordingDNS(DNSError("nope")), 0, 1)
    assert (await issuer._issue(FakeACME(authorization("b")), JWK, ["b"]))[1] == b"chain"
    assert caplog.record_tuples == [
        ("wildburrow.certs.acme", logging.WARNING, "could not remove a challenge record: nope")
    ]


@pytest.mark.parametrize(("email", "contact"), [("ops@example.com", ("mailto:ops@example.com",)), ("", ())])
def test_the_account_is_private_and_registered_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, email: str, contact: tuple[str, ...]
) -> None:
    networks: list[SimpleNamespace] = []
    registrations: list[messages.NewRegistration] = []

    class Network(SimpleNamespace):
        def __init__(self, jwk: josepy.JWKEC, alg: object, user_agent: str) -> None:
            super().__init__(jwk=jwk, user_agent=user_agent, account=None)
            networks.append(self)

    class Client:
        get_directory = staticmethod(lambda url, net: url)

        def __init__(self, directory: str, net: Network) -> None:
            assert directory == DIRECTORY

        def new_account(self, registration: messages.NewRegistration) -> messages.RegistrationResource:
            registrations.append(registration)
            return messages.RegistrationResource(body=registration, uri="https://acme.invalid/account/1")

    monkeypatch.setattr(acme_module.client, "ClientNetwork", Network)
    monkeypatch.setattr(acme_module.client, "ClientV2", Client)
    _, jwk = ACMEIssuer(DIRECTORY, email, tmp_path, RecordingDNS(), 0, 1)._connect()
    _, again = ACMEIssuer(DIRECTORY, email, tmp_path, RecordingDNS(), 0, 1)._connect()

    state = tmp_path / hashlib.sha256(DIRECTORY.encode()).hexdigest()[:16]
    assert sorted(path.name for path in tmp_path.iterdir()) == [state.name]
    assert sorted(path.name for path in state.iterdir()) == ["account.json", "account.key"]
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "account.key").stat().st_mode) == 0o600
    assert [(r.contact, r.terms_of_service_agreed) for r in registrations] == [(contact, True)]
    assert [(n.user_agent, n.account) for n in networks] == [("wildburrow", None), ("wildburrow", networks[1].account)]
    assert networks[1].account.uri == "https://acme.invalid/account/1"
    assert again.thumbprint() == jwk.thumbprint()


def test_the_store_layout(tmp_path: Path) -> None:
    store = CertStore(tmp_path)
    store.save("foo", *self_signed(["*.foo"], NOW + timedelta(days=5)))
    assert sorted(path.name for path in (tmp_path / "foo").iterdir()) == ["chain.pem", "key.pem"]
    assert stat.S_IMODE((tmp_path / "foo" / "chain.pem").stat().st_mode) == 0o644


async def test_certificates_expire_and_renew_on_the_boundary(tmp_path: Path) -> None:
    clock = Clock()
    issuer = FakeIssuer(lifetime=timedelta(days=40))
    certs = manager(tmp_path, issuer, clock=clock)
    await certs.ensure(DOMAIN)
    clock.now = NOW + timedelta(days=10)
    await certs.renew_due([])
    assert len(issuer.calls) == 1
    clock.now = NOW + timedelta(days=40)
    assert not certs.ready(DOMAIN)


async def test_a_failed_certificate_is_logged_and_releases_the_name(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ctx = ServerContext(DOMAIN, 5, tmp_path, Authenticator([]))
    ctx.certs = manager(tmp_path, FakeIssuer(fail=1))
    tunnel = FakeTunnel(Identity("a", "key", "a"))
    with pytest.raises(
        CertificateFailed, match=rf"^could not get a certificate for \*\.{re.escape(DOMAIN)}: issuance failed$"
    ):
        await ctx.bind("app", tunnel, lambda text: None)
    assert ctx.registry.names() == []
    assert [(r.name, r.levelno, r.getMessage()) for r in caplog.records] == [
        ("wildburrow.core.context", logging.ERROR, f"certificate for *.{DOMAIN} failed")
    ]


async def test_issuing_and_failing_are_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    clock = Clock()
    issuer = FakeIssuer(lifetime=timedelta(days=40))
    certs = manager(tmp_path, issuer, clock=clock)
    await certs.ensure(f"app.{DOMAIN}")
    await certs.ensure(DOMAIN)
    clock.now += timedelta(days=15)
    issuer.fail = 1
    await certs.renew_due([])
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (logging.INFO, f"requesting a certificate for *.app.{DOMAIN}"),
        (logging.INFO, f"requesting a certificate for *.{DOMAIN}, {DOMAIN}"),
        (logging.INFO, f"requesting a certificate for *.{DOMAIN}, {DOMAIN}"),
        (logging.ERROR, f"renewing *.{DOMAIN} failed; will retry"),
    ]


class Certificates:
    """What a manager writes in the server's record, with ids as a record keeping history hands out."""

    def __init__(self, history: bool = True) -> None:
        self.history = history
        self.seen: list[tuple[object, ...]] = []

    def certificate_requested(self, parent: str) -> int | None:
        self.seen.append(("requested", parent))
        return len(self.seen) if self.history else None

    def certificate_finished(self, certificate: int, error: str | None) -> None:
        self.seen.append(("finished", certificate, error))


@pytest.mark.parametrize(("failure", "error"), [(RuntimeError("rate limited"), "rate limited"), (OSError(), "OSError")])
async def test_every_certificate_asked_for_is_recorded_with_how_it_went(
    tmp_path: Path, failure: Exception, error: str
) -> None:
    record = Certificates()
    certs = CertManager(
        DOMAIN, CertStore(tmp_path / "certs"), FakeIssuer(), FakeDNS(), False, timedelta(days=30), Clock(), record
    )  # type: ignore[arg-type]
    await certs.ensure(f"app.{DOMAIN}")
    certs._issuer.issue = lambda domains: _raise(failure)  # type: ignore[method-assign]
    with pytest.raises(type(failure)):
        await certs.ensure(f"x.app.{DOMAIN}")
    assert record.seen == [
        ("requested", f"app.{DOMAIN}"),
        ("finished", 1, None),
        ("requested", f"x.app.{DOMAIN}"),
        ("finished", 3, error),
    ]


async def _raise(failure: Exception) -> tuple[bytes, bytes]:
    raise failure


@pytest.mark.parametrize("fail", [0, 1])
async def test_a_record_without_history_is_told_nothing_more(tmp_path: Path, fail: int) -> None:
    record = Certificates(history=False)
    certs = CertManager(
        DOMAIN, CertStore(tmp_path / "certs"), FakeIssuer(fail=fail), FakeDNS(), False, timedelta(days=30), Clock(),
        record,  # type: ignore[arg-type]
    )  # fmt: skip
    with pytest.raises(RuntimeError) if fail else contextlib.nullcontext():
        await certs.ensure(f"app.{DOMAIN}")
    assert record.seen == [("requested", f"app.{DOMAIN}")]


async def test_maintain_says_when_it_retries(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    certs = manager(tmp_path, FakeIssuer(fail=1))
    task = asyncio.create_task(certs.maintain(list, interval=60, retry=0))
    async with asyncio.timeout(5):
        while not certs.ready(DOMAIN):
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR] == [
        f"getting the *.{DOMAIN} certificate failed; retrying in 0s"
    ]
