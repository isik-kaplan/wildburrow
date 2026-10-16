from dataclasses import dataclass
from typing import Any

import httpx

from wildburrow.config import ConfigError
from wildburrow.dns.base import DNSError

API = "https://api.cloudflare.com/client/v4"
TXT_TTL = 60
AUTOMATIC_TTL = 1


@dataclass(frozen=True, slots=True)
class CloudflareSettings:
    api_token: str


class CloudflareDNS:
    Settings = CloudflareSettings

    def __init__(self, settings: CloudflareSettings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not settings.api_token:
            raise ConfigError("api_token is empty")
        self._client = httpx.AsyncClient(
            base_url=API, headers={"Authorization": f"Bearer {settings.api_token}"}, transport=transport, timeout=30
        )
        self._zones: dict[str, str] = {}

    async def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = await self._client.request(method, path, **kwargs)
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DNSError(f"Cloudflare {method} {path}: {exc}") from exc
        if not data.get("success"):
            raise DNSError(f"Cloudflare {method} {path}: {data.get('errors')}")
        return data["result"]

    async def _zone(self, fqdn: str) -> str:
        labels = fqdn.removeprefix("*.").split(".")
        candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
        for name in candidates:
            if name in self._zones:
                return self._zones[name]
        for name in candidates:
            if zones := await self._call("GET", "/zones", params={"name": name}):
                self._zones[name] = zones[0]["id"]
                return self._zones[name]
        raise DNSError(f"no Cloudflare zone found for {fqdn}")

    async def create_txt(self, fqdn: str, value: str) -> tuple[str, str]:
        zone = await self._zone(fqdn)
        body = {"type": "TXT", "name": fqdn, "content": value, "ttl": TXT_TTL}
        record = await self._call("POST", f"/zones/{zone}/dns_records", json=body)
        return zone, record["id"]

    async def delete_txt(self, record: object) -> None:
        zone, record_id = record  # type: ignore[misc]
        await self._call("DELETE", f"/zones/{zone}/dns_records/{record_id}")

    async def ensure_cname(self, fqdn: str, target: str) -> None:
        zone = await self._zone(fqdn)
        if await self._call("GET", f"/zones/{zone}/dns_records", params={"name": fqdn}):
            return
        body = {"type": "CNAME", "name": fqdn, "content": target, "ttl": AUTOMATIC_TTL, "proxied": False}
        await self._call("POST", f"/zones/{zone}/dns_records", json=body)

    async def aclose(self) -> None:
        await self._client.aclose()
