from pathlib import Path

from wildburrow.service import DATA_DIR, ENV_PATH, NAME, Account, checked, command, run

UNIT = Path(f"etc/systemd/system/{NAME}.service")
STATE = Path(f"var/lib/{NAME}")
# Where systemd keeps the state of a throwaway user, behind the link at STATE.
PRIVATE_STATE = Path(f"var/lib/private/{NAME}")


def _quote(word: str) -> str:
    return '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'


def unit(account: Account) -> str:
    user = "DynamicUser=yes" if account.name is None else f"User={account.name}"
    # A service running as an install's owner reads its code from their home, so it can't hide it.
    home = "yes" if account.name is None else "read-only"
    return f"""[Unit]
Description=wildburrow tunnel server
Wants=network-online.target
After=network-online.target

[Service]
ExecStart={" ".join(_quote(word) for word in command())}
EnvironmentFile={ENV_PATH}
Environment={DATA_DIR}=%S/{NAME}
{user}
StateDirectory={NAME}
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome={home}
PrivateTmp=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


class Systemd:
    kind = "systemd"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.unit = root / UNIT

    def data_dirs(self) -> list[Path]:
        return [self.root / STATE, self.root / PRIVATE_STATE]

    def file_owner(self, account: Account) -> Account:
        # systemd reads the environment file itself, as root, before starting the service.
        return Account(None)

    def installed(self) -> bool:
        return self.unit.exists()

    def install(self, account: Account) -> None:
        self.unit.parent.mkdir(parents=True, exist_ok=True)
        self.unit.write_text(unit(account))
        self.unit.chmod(0o644)
        checked("systemctl", "daemon-reload")
        checked("systemctl", "enable", "--now", NAME)

    def uninstall(self) -> None:
        run("systemctl", "disable", "--now", NAME)
        self.unit.unlink(missing_ok=True)
        checked("systemctl", "daemon-reload")

    def restart(self) -> None:
        checked("systemctl", "restart", NAME)

    def status(self) -> str:
        return run("systemctl", "is-active", NAME).stdout.strip() or "unknown"

    def logs(self) -> str:
        return f"journalctl -u {NAME} -f"
