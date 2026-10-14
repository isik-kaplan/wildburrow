import asyncio
import ssl

import pytest
from cryptography import x509

from tests import acme_env
from tests.conftest import DOMAIN, TIMEOUT, Backend, Connect, Running, StartServer, get, http

pytestmark = [pytest.mark.e2e, pytest.mark.acme]


def forward(name: str, port: int) -> list[str]:
    return ["-R", f"{name}:80:127.0.0.1:{port}"]


def client_context(pebble: acme_env.Pebble) -> ssl.SSLContext:
    context = ssl.create_default_context(cadata=pebble.root())
    context.set_alpn_protocols(["http/1.1"])
    return context


async def https(
    running: Running, pebble: acme_env.Pebble, sni: str | None, host: str, path: str = "/"
) -> tuple[bytes, x509.Certificate]:
    context = client_context(pebble)
    if sni is None:
        context.check_hostname = False
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", running.https_port, ssl=context, server_hostname=sni or ""
    )
    der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    async with asyncio.timeout(TIMEOUT):
        response = await reader.read()
    writer.close()
    return response, x509.load_der_x509_certificate(der)


def san(cert: x509.Certificate) -> list[str]:
    return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)


async def test_certificates_are_issued_per_wildcard(
    start_server: StartServer, connect: Connect, backend: Backend, pebble: acme_env.Pebble, tls_env: dict[str, str]
) -> None:
    running = await start_server(**tls_env)
    client = await connect(running.ssh_port, "key", *forward("solo", backend.port), *forward("*.bar.foo", backend.port))
    assert await client.line("ready: https://solo.") == f"ready: https://solo.{DOMAIN}"
    await client.line(f"issuing a certificate for *.bar.foo.{DOMAIN}")
    assert await client.line("ready: https://*.bar.foo.") == f"ready: https://*.bar.foo.{DOMAIN}"

    response, cert = await https(running, pebble, f"solo.{DOMAIN}", f"solo.{DOMAIN}", "/x")
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert response.endswith(b"GET /x HTTP/1.1")
    assert sorted(san(cert)) == sorted([f"*.{DOMAIN}", DOMAIN])

    response, cert = await https(running, pebble, f"api.bar.foo.{DOMAIN}", f"API.bar.foo.{DOMAIN}:443")
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert san(cert) == [f"*.bar.foo.{DOMAIN}"]


async def test_plain_http_redirects_bound_names_only(
    start_server: StartServer, connect: Connect, backend: Backend, tls_env: dict[str, str]
) -> None:
    running = await start_server(**tls_env)
    client = await connect(running.ssh_port, "key", *forward("*.foo", backend.port))
    await client.line("ready:")
    status, _ = await get(running.http_port, f"a.foo.{DOMAIN}", "/p?q=1")
    assert status == 308
    response = await http(running.http_port, f"GET /p?q=1 HTTP/1.1\r\nHost: a.foo.{DOMAIN}\r\n\r\n".encode())
    assert f"\r\nLocation: https://a.foo.{DOMAIN}/p?q=1\r\n".encode() in response
    assert (await get(running.http_port, f"a.other.{DOMAIN}"))[0] == 404
    assert (await get(running.http_port, "evil.example.org"))[0] == 404
    assert backend.requests == []


async def test_host_must_be_covered_by_the_presented_certificate(
    start_server: StartServer, connect: Connect, backend: Backend, pebble: acme_env.Pebble, tls_env: dict[str, str]
) -> None:
    running = await start_server(**tls_env)
    client = await connect(running.ssh_port, "key", *forward("*.foo", backend.port), *forward("other", backend.port))
    await client.line("ready: https://*.foo")
    await client.line("ready: https://other")
    response, _ = await https(running, pebble, f"a.foo.{DOMAIN}", f"other.{DOMAIN}")
    assert response.startswith(b"HTTP/1.1 421 ")
    assert backend.requests == []


@pytest.mark.parametrize("sni", [None, "x.unbound.tunnel.test", "elsewhere.example.org"])
async def test_handshake_fails_without_a_matching_certificate(
    start_server: StartServer, connect: Connect, backend: Backend, pebble: acme_env.Pebble, tls_env, sni
) -> None:
    running = await start_server(**tls_env)
    client = await connect(running.ssh_port, "key", *forward("solo", backend.port))
    await client.line("ready:")
    with pytest.raises((ssl.SSLError, ConnectionResetError)):
        await https(running, pebble, sni, f"solo.{DOMAIN}")


async def test_certificates_survive_restarts(
    start_server: StartServer, connect: Connect, backend: Backend, pebble, tls_env: dict[str, str], tmp_path
) -> None:
    first = await start_server(**tls_env)
    client = await connect(first.ssh_port, "key", *forward("*.foo", backend.port))
    await client.line("issuing")
    await client.line("ready:")
    await client.close()

    second = await start_server(**tls_env)
    client = await connect(second.ssh_port, "key", *forward("*.foo", backend.port), *forward("*.bar", backend.port))
    assert await client.line("ready:") == f"ready: https://*.foo.{DOMAIN}"
    assert [line for line in client.lines if line.startswith("issuing")] == []
    response, _ = await https(second, pebble, f"a.foo.{DOMAIN}", f"a.foo.{DOMAIN}")
    assert response.startswith(b"HTTP/1.1 200 OK")
    await client.line(f"issuing a certificate for *.bar.{DOMAIN}")
    assert await client.line("ready:") == f"ready: https://*.bar.{DOMAIN}"
    assert len(list((tmp_path / "data" / "acme").iterdir())) == 1


async def test_certificates_in_use_are_renewed(
    start_server: StartServer, connect: Connect, backend: Backend, pebble: acme_env.Pebble, tls_env: dict[str, str]
) -> None:
    running = await start_server(**tls_env, WILDBURROW_RENEW_BEFORE_DAYS="36500", WILDBURROW_RENEW_INTERVAL_SECONDS="1")
    client = await connect(running.ssh_port, "key", *forward("*.foo", backend.port))
    await client.line("ready:")
    _, first = await https(running, pebble, f"a.foo.{DOMAIN}", f"a.foo.{DOMAIN}")
    async with asyncio.timeout(TIMEOUT):
        while True:
            _, current = await https(running, pebble, f"a.foo.{DOMAIN}", f"a.foo.{DOMAIN}")
            if current.serial_number != first.serial_number:
                break
            await asyncio.sleep(0.2)
    assert san(current) == [f"*.foo.{DOMAIN}"]


async def test_failed_issuance_rejects_the_bind(
    start_server: StartServer, connect: Connect, backend: Backend, tls_env: dict[str, str]
) -> None:
    running = await start_server(**tls_env, WILDBURROW_DNS_CHALLTESTSRV_CORRUPT="true")
    client = await connect(running.ssh_port, "key", *forward("*.foo", backend.port))
    await client.line("issuing")
    assert (await client.line("rejected:")).startswith(f"rejected: could not get a certificate for *.foo.{DOMAIN}")
    assert await client.wait() != 0
    assert running.server.ctx.registry.names() == []


async def test_records_are_managed_for_nested_wildcards(
    start_server: StartServer, connect: Connect, backend: Backend, tls_env: dict[str, str]
) -> None:
    running = await start_server(
        **tls_env, WILDBURROW_DNS_MANAGE_RECORDS="true", WILDBURROW_DNS_CHALLTESTSRV_FAIL_CLEANUP="true"
    )
    client = await connect(running.ssh_port, "key", *forward("*.bar.foo", backend.port))
    await client.line("ready:")
    assert (f"*.bar.foo.{DOMAIN}", DOMAIN) in running.server.dns.cnames
    assert all(fqdn != f"*.{DOMAIN}" for fqdn, _ in running.server.dns.cnames)


async def test_disconnect_during_issuance_frees_the_name(
    start_server: StartServer, connect: Connect, backend: Backend, tls_env: dict[str, str]
) -> None:
    running = await start_server(**{**tls_env, "WILDBURROW_ACME_PROPAGATION_SECONDS": "2"})
    client = await connect(running.ssh_port, "key", *forward("*.slow", backend.port))
    await client.line("issuing")
    client.process.kill()
    await client.process.wait()
    async with asyncio.timeout(TIMEOUT):
        while running.server.ctx.certs.ready(f"slow.{DOMAIN}") is False:
            await asyncio.sleep(0.1)
    await asyncio.sleep(0.2)
    assert running.server.ctx.registry.names() == []


async def test_proxy_protocol_before_the_tls_handshake(
    start_server: StartServer, connect: Connect, backend: Backend, pebble: acme_env.Pebble, tls_env: dict[str, str]
) -> None:
    running = await start_server(**tls_env, WILDBURROW_HTTPS_PROXY_PROTOCOL="true")
    client = await connect(running.ssh_port, "key", *forward("solo", backend.port))
    await client.line("ready:")
    reader, writer = await asyncio.open_connection("127.0.0.1", running.https_port)
    writer.write(b"PROXY TCP4 203.0.113.9 10.0.0.1 51000 443\r\n")
    await writer.start_tls(client_context(pebble), server_hostname=f"solo.{DOMAIN}")
    writer.write(f"GET /p HTTP/1.1\r\nHost: solo.{DOMAIN}\r\n\r\n".encode())
    async with asyncio.timeout(TIMEOUT):
        response = await reader.read()
    writer.close()
    assert response.startswith(b"HTTP/1.1 200 OK")
    with pytest.raises((ssl.SSLError, ConnectionResetError)):
        await https(running, pebble, f"solo.{DOMAIN}", f"solo.{DOMAIN}")
