"""A DNS provider whose every change goes in the server's record, whether it worked or not."""

from collections.abc import Awaitable
from typing import Any

from wildburrow.dns.base import DNSProvider
from wildburrow.store.record import Recorder


class RecordedDNS:
    def __init__(self, dns: DNSProvider, record: Recorder) -> None:
        self._dns = dns
        self._record = record
        # Each TXT record made, by what the provider handed back, so deleting it names it.
        self._names: dict[int, str] = {}

    async def _changed(self, action: str, name: str, value: str | None, work: Awaitable[Any]) -> Any:
        try:
            result = await work
        except Exception as exc:
            self._record.dns_change(action, name, value, str(exc) or type(exc).__name__)
            raise
        self._record.dns_change(action, name, value, None)
        return result

    async def create_txt(self, fqdn: str, value: str) -> object:
        made = await self._changed("create-txt", fqdn, value, self._dns.create_txt(fqdn, value))
        self._names[id(made)] = fqdn
        return made

    async def delete_txt(self, record: object) -> None:
        name = self._names.pop(id(record), str(record))
        await self._changed("delete-txt", name, None, self._dns.delete_txt(record))

    async def ensure_cname(self, fqdn: str, target: str) -> None:
        await self._changed("cname", fqdn, target, self._dns.ensure_cname(fqdn, target))

    async def aclose(self) -> None:
        await self._dns.aclose()
