import ssl
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx

PEBBLE = "ghcr.io/letsencrypt/pebble:2.10.1"
CHALLTESTSRV = "ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1"


@dataclass(frozen=True)
class Pebble:
    directory: str
    management: str
    challtestsrv: str
    minica: Path

    def root(self) -> str:
        return httpx.get(f"{self.management}/roots/0", verify=trust(self.minica)).text


def trust(ca: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(ca))


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def _port(container: str, port: int) -> int:
    return int(_docker("port", container, f"{port}/tcp").splitlines()[0].rsplit(":", 1)[1])


def start(workdir: Path) -> tuple[Pebble, list[str]]:
    suffix = uuid.uuid4().hex[:8]
    network, dns, pebble = f"wb-{suffix}", f"wb-dns-{suffix}", f"wb-pebble-{suffix}"
    _docker("network", "create", network)
    _docker(
        "run",
        "-d",
        "--rm",
        "--name",
        dns,
        "--network",
        network,
        "--network-alias",
        "challtestsrv",
        "-p",
        "127.0.0.1::8055",
        CHALLTESTSRV,
        "-http01",
        "",
        "-https01",
        "",
        "-tlsalpn01",
        "",
        "-doh",
        "",
    )
    _docker("run", "-d", "--rm", "--name", pebble, "--network", network,
            "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0", "-e", "PEBBLE_AUTHZREUSE=100",
            "-p", "127.0.0.1::14000", "-p", "127.0.0.1::15000",
            PEBBLE, "-dnsserver", "challtestsrv:8053")  # fmt: skip
    minica = workdir / "pebble.minica.pem"
    _docker("cp", f"{pebble}:/test/certs/pebble.minica.pem", str(minica))
    env = Pebble(
        directory=f"https://localhost:{_port(pebble, 14000)}/dir",
        management=f"https://localhost:{_port(pebble, 15000)}",
        challtestsrv=f"http://127.0.0.1:{_port(dns, 8055)}",
        minica=minica,
    )
    deadline = time.monotonic() + 30
    while True:
        try:
            httpx.get(env.directory, verify=trust(minica)).raise_for_status()
            httpx.post(f"{env.challtestsrv}/clear-txt", json={"host": "ready."}).raise_for_status()
            break
        except httpx.HTTPError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)
    return env, [pebble, dns, network]


def stop(resources: list[str]) -> None:
    *containers, network = resources
    subprocess.run(["docker", "rm", "-f", *containers], check=False, capture_output=True)
    subprocess.run(["docker", "network", "rm", network], check=False, capture_output=True)


def register_test_plugins(root: Path) -> Path:
    dist = root / "wildburrow_test_plugins-0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: wildburrow-test-plugins\nVersion: 0\n")
    (dist / "entry_points.txt").write_text(
        "[wildburrow.dns]\nchalltestsrv = tests.plugins.challtestsrv:ChallTestSrvDNS\n"
    )
    return root
