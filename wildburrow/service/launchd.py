import plistlib
from pathlib import Path

from wildburrow.service import DATA_DIR, ENV_PATH, NAME, Account, ServiceError, checked, command, own, run

LABEL = NAME
PLIST = Path(f"Library/LaunchDaemons/{LABEL}.plist")
STATE = Path(f"Library/Application Support/{NAME}")
LOG = Path(f"Library/Logs/{NAME}.log")
TARGET = f"system/{LABEL}"


def _absolute(path: Path) -> str:
    return str(Path("/") / path)


def plist(account: Account) -> bytes:
    job: dict[str, object] = {
        "Label": LABEL,
        "ProgramArguments": [*command(), "--env-file", str(ENV_PATH)],
        "EnvironmentVariables": {DATA_DIR: _absolute(STATE)},
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": _absolute(LOG),
        "StandardErrorPath": _absolute(LOG),
    }
    if account.name is not None:
        job["UserName"] = account.name
    return plistlib.dumps(job)


class Launchd:
    kind = "launchd"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.plist = root / PLIST

    def data_dirs(self) -> list[Path]:
        return [self.root / STATE]

    def file_owner(self, account: Account) -> Account:
        # launchd starts the server as the account, which then reads its own settings.
        return account

    def installed(self) -> bool:
        return self.plist.exists()

    def install(self, account: Account) -> None:
        data = self.root / STATE
        data.mkdir(mode=0o700, parents=True, exist_ok=True)
        own(data, account)
        log = self.root / LOG
        log.parent.mkdir(exist_ok=True)
        log.touch(mode=0o640)
        own(log, account)
        self.plist.parent.mkdir(exist_ok=True)
        self.plist.write_bytes(plist(account))
        self.plist.chmod(0o644)
        checked("launchctl", "bootstrap", "system", str(self.plist))

    def uninstall(self) -> None:
        run("launchctl", "bootout", TARGET)
        self.plist.unlink(missing_ok=True)
        (self.root / LOG).unlink(missing_ok=True)

    def restart(self) -> None:
        checked("launchctl", "kickstart", "-k", TARGET)

    def status(self) -> str:
        result = run("launchctl", "print", TARGET)
        if result.returncode != 0:
            return "not loaded"
        for line in result.stdout.splitlines():
            key, _, value = line.strip().partition(" = ")
            if key == "state":
                return value
        raise ServiceError(f"`launchctl print {TARGET}` shows no state")

    def logs(self) -> str:
        return f"tail -f {_absolute(LOG)!r}"
