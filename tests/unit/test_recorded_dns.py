import pytest

from wildburrow.dns.recorded import RecordedDNS


class Provider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    async def create_txt(self, fqdn: str, value: str) -> object:
        self.calls.append(("create", fqdn, value))
        return {"id": "r1"}

    async def delete_txt(self, record: object) -> None:
        self.calls.append(("delete", str(record)))

    async def ensure_cname(self, fqdn: str, target: str) -> None:
        if fqdn.startswith("bad"):
            raise RuntimeError
        if fqdn.startswith("worse"):
            raise RuntimeError("zone is read-only")
        self.calls.append(("cname", fqdn, target))

    async def aclose(self) -> None:
        self.calls.append(("close",))


class Changes:
    def __init__(self) -> None:
        self.seen: list[tuple[object, ...]] = []

    def dns_change(self, *change: object) -> None:
        self.seen.append(change)


async def test_every_change_is_recorded_whether_it_worked_or_not() -> None:
    provider, changes = Provider(), Changes()
    dns = RecordedDNS(provider, changes)  # type: ignore[arg-type]
    made = await dns.create_txt("_acme.example.com", "v")
    await dns.delete_txt(made)
    await dns.delete_txt("unknown")
    await dns.ensure_cname("*.foo.example.com", "example.com")
    for name, error in (("bad.example.com", "RuntimeError"), ("worse.example.com", "zone is read-only")):
        with pytest.raises(RuntimeError):
            await dns.ensure_cname(name, "example.com")
        assert changes.seen[-1] == ("cname", name, "example.com", error)
    await dns.aclose()
    assert changes.seen[:4] == [
        ("create-txt", "_acme.example.com", "v", None),
        ("delete-txt", "_acme.example.com", None, None),
        ("delete-txt", "unknown", None, None),
        ("cname", "*.foo.example.com", "example.com", None),
    ]
    assert provider.calls == [
        ("create", "_acme.example.com", "v"),
        ("delete", "{'id': 'r1'}"),
        ("delete", "unknown"),
        ("cname", "*.foo.example.com", "example.com"),
        ("close",),
    ]
