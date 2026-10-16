import json

import httpx
import pytest

from wildburrow.config import ConfigError
from wildburrow.dns.base import DNSError
from wildburrow.dns.cloudflare import CloudflareDNS, CloudflareSettings

TOKEN = "cf-token"


class FakeCloudflare:
    def __init__(self, zones: dict[str, str]) -> None:
        self.zones = zones
        self.records: dict[str, dict] = {}
        self.requests: list[tuple[str, str]] = []
        self.queried: list[str] = []
        self.failures: dict[int, httpx.Response | Exception] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        if failure := self.failures.get(len(self.requests)):
            self.requests.append((request.method, request.url.path))
            if isinstance(failure, Exception):
                raise failure
            return failure
        self.requests.append((request.method, request.url.path))
        path = request.url.path.removeprefix("/client/v4")
        if path == "/zones":
            assert request.method == "GET"
            name = request.url.params["name"]
            self.queried.append(name)
            result = [{"id": self.zones[name], "name": name}] if name in self.zones else []
            return self.ok(result)
        zone, _, rest = path.removeprefix("/zones/").partition("/")
        assert zone in self.zones.values()
        if request.method == "POST":
            record = {"id": f"r{len(self.records)}", **json.loads(request.content)}
            self.records[record["id"]] = record
            return self.ok(record)
        if request.method == "DELETE":
            del self.records[rest.removeprefix("dns_records/")]
            return self.ok({})
        assert request.method == "GET"
        name = request.url.params["name"]
        return self.ok([r for r in self.records.values() if r["name"] == name])

    @staticmethod
    def ok(result: object) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "errors": [], "result": result})


def provider(fake: FakeCloudflare, **settings: str) -> CloudflareDNS:
    return CloudflareDNS(CloudflareSettings(**({"api_token": TOKEN} | settings)), httpx.MockTransport(fake))


async def test_txt_records_land_in_the_closest_zone() -> None:
    fake = FakeCloudflare({"example.com": "z1", "sub.example.com": "z2"})
    dns = provider(fake)
    record = await dns.create_txt("_acme-challenge.a.sub.example.com", "value")
    assert record == ("z2", "r0")
    assert fake.records["r0"] == {
        "id": "r0", "type": "TXT", "name": "_acme-challenge.a.sub.example.com", "content": "value", "ttl": 60,
    }  # fmt: skip
    await dns.create_txt("_acme-challenge.b.sub.example.com", "other")
    assert [p for m, p in fake.requests if p.endswith("/zones")] == ["/client/v4/zones"] * 3
    await dns.delete_txt(record)
    assert "r0" not in fake.records
    await dns.aclose()


async def test_cname_is_created_once() -> None:
    fake = FakeCloudflare({"example.com": "z1"})
    dns = provider(fake)
    await dns.ensure_cname("*.foo.tunnel.example.com", "tunnel.example.com")
    await dns.ensure_cname("*.foo.tunnel.example.com", "tunnel.example.com")
    assert fake.queried == ["foo.tunnel.example.com", "tunnel.example.com", "example.com"]
    assert list(fake.records.values()) == [
        {"id": "r0", "type": "CNAME", "name": "*.foo.tunnel.example.com", "content": "tunnel.example.com",
         "ttl": 1, "proxied": False},
    ]  # fmt: skip


OPERATIONS = {
    "create_txt": lambda dns: dns.create_txt("_acme-challenge.example.com", "v"),
    "delete_txt": lambda dns: dns.delete_txt(("z1", "r0")),
    "ensure_cname": lambda dns: dns.ensure_cname("app.example.com", "example.com"),
}


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (httpx.Response(200, json={"success": False, "errors": [{"code": 9109}]}), "[{'code': 9109}]"),
        (httpx.Response(502, text="<html>bad gateway</html>"), "Expecting value: line 1 column 1 (char 0)"),
        (httpx.ConnectError("refused"), "refused"),
    ],
)
@pytest.mark.parametrize(
    ("operation", "request_number", "call"),
    [
        ("create_txt", 0, "GET /zones"),
        ("create_txt", 2, "POST /zones/z1/dns_records"),
        ("delete_txt", 0, "DELETE /zones/z1/dns_records/r0"),
        ("ensure_cname", 2, "GET /zones/z1/dns_records"),
        ("ensure_cname", 3, "POST /zones/z1/dns_records"),
    ],
)
async def test_api_failures_raise_dns_errors(
    failure: httpx.Response | Exception, message: str, operation: str, request_number: int, call: str
) -> None:
    fake = FakeCloudflare({"example.com": "z1"})
    fake.failures[request_number] = failure
    with pytest.raises(DNSError) as error:
        await OPERATIONS[operation](provider(fake))
    assert str(error.value) == f"Cloudflare {call}: {message}"


async def test_missing_zone() -> None:
    fake = FakeCloudflare({})
    with pytest.raises(DNSError) as error:
        await provider(fake).create_txt("x.example.org", "v")
    assert str(error.value) == "no Cloudflare zone found for x.example.org"
    assert fake.queried == ["x.example.org", "example.org"]


def test_requests_are_authorized_and_bounded() -> None:
    assert provider(FakeCloudflare({}))._client.timeout == httpx.Timeout(30)


def test_token_is_required() -> None:
    with pytest.raises(ConfigError) as error:
        provider(FakeCloudflare({}), api_token="")
    assert str(error.value) == "api_token is empty"
