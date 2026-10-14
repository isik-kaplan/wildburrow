import json
import re
from pathlib import Path

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
        self.fail_next: httpx.Response | Exception | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        self.requests.append((request.method, request.url.path))
        if self.fail_next is not None:
            failure, self.fail_next = self.fail_next, None
            if isinstance(failure, Exception):
                raise failure
            return failure
        path = request.url.path.removeprefix("/client/v4")
        if path == "/zones":
            name = request.url.params["name"]
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
    assert list(fake.records.values()) == [
        {"id": "r0", "type": "CNAME", "name": "*.foo.tunnel.example.com", "content": "tunnel.example.com",
         "ttl": 1, "proxied": False},
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (httpx.Response(200, json={"success": False, "errors": [{"code": 9109}]}), "9109"),
        (httpx.Response(502, text="<html>bad gateway</html>"), "Cloudflare GET /zones"),
        (httpx.ConnectError("refused"), "refused"),
    ],
)
async def test_api_failures_raise_dns_errors(failure: httpx.Response | Exception, message: str) -> None:
    fake = FakeCloudflare({"example.com": "z1"})
    fake.fail_next = failure
    with pytest.raises(DNSError, match=message):
        await provider(fake).create_txt("_acme-challenge.example.com", "v")


async def test_missing_zone() -> None:
    with pytest.raises(DNSError, match=re.escape("no Cloudflare zone found for x.example.org")):
        await provider(FakeCloudflare({})).create_txt("x.example.org", "v")


def test_token_from_file(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text(f"{TOKEN}\n")
    assert isinstance(provider(FakeCloudflare({}), api_token="", api_token_file=str(path)), CloudflareDNS)


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        ({"api_token": ""}, "api_token or api_token_file is required"),
        ({"api_token": "", "api_token_file": "/nonexistent/token"}, "api_token_file:"),
    ],
)
def test_token_errors(settings: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        provider(FakeCloudflare({}), **settings)
