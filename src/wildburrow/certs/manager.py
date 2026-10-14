import asyncio
import logging
import ssl
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta

from wildburrow.certs.acme import Issuer
from wildburrow.certs.store import CertStore
from wildburrow.core.names import Name, host_labels
from wildburrow.dns.base import DNSProvider

log = logging.getLogger(__name__)

ALPN = ["http/1.1"]


def server_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(ALPN)
    return context


class CertManager:
    def __init__(
        self,
        domain: str,
        store: CertStore,
        issuer: Issuer,
        dns: DNSProvider,
        manage_records: bool,
        renew_before: timedelta,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.domain = domain
        self._store = store
        self._issuer = issuer
        self._dns = dns
        self._manage_records = manage_records
        self._renew_before = renew_before
        self._clock = clock
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._inflight: dict[str, asyncio.Task[None]] = {}

    def parent(self, name: Name) -> str:
        labels = name.labels if name.wildcard else name.labels[1:]
        return ".".join((*labels, self.domain))

    def ready(self, parent: str) -> bool:
        stored = self._store.load(parent)
        return stored is not None and stored.expires > self._clock()

    async def ensure(self, parent: str) -> None:
        if not self.ready(parent):
            await self._issue(parent)

    async def _issue(self, parent: str) -> None:
        task = self._inflight.get(parent)
        if task is None:
            task = asyncio.create_task(self._obtain(parent))
            self._inflight[parent] = task
            task.add_done_callback(lambda _: self._inflight.pop(parent, None))
        await asyncio.shield(task)

    async def _obtain(self, parent: str) -> None:
        if self._manage_records and parent != self.domain:
            await self._dns.ensure_cname(f"*.{parent}", self.domain)
        domains = [f"*.{parent}", parent] if parent == self.domain else [f"*.{parent}"]
        log.info("requesting a certificate for %s", ", ".join(domains))
        key_pem, chain_pem = await self._issuer.issue(domains)
        self._store.save(parent, key_pem, chain_pem)
        self._contexts.pop(parent, None)

    def context_for(self, server_name: str | None) -> ssl.SSLContext | None:
        if server_name is None:
            return None
        server_name = server_name.lower()
        if server_name == self.domain:
            parent = self.domain
        elif (labels := host_labels(server_name, self.domain)) is not None:
            parent = ".".join((*labels[1:], self.domain))
        else:
            return None
        if parent not in self._contexts:
            stored = self._store.load(parent)
            if stored is None:
                return None
            context = server_context()
            context.load_cert_chain(stored.chain, stored.key)
            self._contexts[parent] = context
        return self._contexts[parent]

    def sni_callback(self, sslobj: ssl.SSLObject, server_name: str | None, _: ssl.SSLContext) -> int | None:
        context = self.context_for(server_name)
        if context is None:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        sslobj.context = context
        return None

    async def renew_due(self, in_use: Iterable[str]) -> None:
        wanted = {self.domain, *in_use}
        for parent in self._store.parents():
            stored = self._store.load(parent)
            if parent in wanted and stored is not None and stored.expires - self._clock() < self._renew_before:
                try:
                    await self._issue(parent)
                except Exception:
                    log.exception("renewing *.%s failed; will retry", parent)

    async def maintain(self, in_use: Callable[[], Iterable[str]], interval: float, retry: float) -> None:
        while True:
            try:
                await self.ensure(self.domain)
            except Exception:
                log.exception("getting the *.%s certificate failed; retrying in %ss", self.domain, retry)
                await asyncio.sleep(retry)
                continue
            await self.renew_due(in_use())
            await asyncio.sleep(interval)
