from dataclasses import dataclass

import httpx

from wildburrow.dns.base import DNSError


@dataclass(frozen=True, slots=True)
class ChallTestSrvSettings:
    url: str
    corrupt: bool = False
    fail_cleanup: bool = False


class ChallTestSrvDNS:
    Settings = ChallTestSrvSettings

    def __init__(self, settings: ChallTestSrvSettings) -> None:
        self._settings = settings
        self.cnames: list[tuple[str, str]] = []
        self._client = httpx.AsyncClient(base_url=settings.url)

    async def create_txt(self, fqdn: str, value: str) -> str:
        content = f"not-{value}" if self._settings.corrupt else value
        (await self._client.post("/set-txt", json={"host": f"{fqdn}.", "value": content})).raise_for_status()
        return fqdn

    async def delete_txt(self, record: object) -> None:
        if self._settings.fail_cleanup:
            raise DNSError("cleanup refused")
        (await self._client.post("/clear-txt", json={"host": f"{record}."})).raise_for_status()

    async def ensure_cname(self, fqdn: str, target: str) -> None:
        self.cnames.append((fqdn, target))

    async def aclose(self) -> None:
        await self._client.aclose()
