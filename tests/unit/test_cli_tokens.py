import asyncio
import json
import re
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import Credentials
from tests.unit.conftest import ENTER, Typist
from wildburrow import cli, tokens
from wildburrow.auth.token import TokenAuth, TokenSettings
from wildburrow.cli import ask as cli_ask
from wildburrow.cli import client as client_cli
from wildburrow.cli import tokens as tokens_cli
from wildburrow.cli.output import when
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, write_config
from wildburrow.config import PREFIX
from wildburrow.core.types import Peer, TokenCredential

SERVER = "tunnel.example.com"


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


class Server:
    """The server `tokens` registers with and lists from: what it was sent, answered as the test set."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], bool]] = []
        self.listed: list[dict[str, Any]] = []
        self.denied_names: dict[str, int] = {}
        self.error: str | websocket.ClientError | None = None
        self.memory = False
        # How many it registers before answering with the error.
        self.partial = 0

    async def tokens(
        self, config: ClientConfig, grants: list[dict[str, Any]], listing: bool, ask: object
    ) -> dict[str, Any]:
        assert ask is cli_ask.password
        self.calls.append((config.server, [grant["id"] for grant in grants], listing))
        if isinstance(self.error, websocket.ClientError):
            raise self.error
        if self.error is not None:
            return {"error": self.error, "registered": [grant["id"] for grant in grants[: self.partial]]}
        answer = {"registered": [grant["id"] for grant in grants], "memory": self.memory}
        return answer | ({"tokens": self.listed, "denied_names": self.denied_names} if listing else {})


@pytest.fixture(autouse=True)
def server(monkeypatch: pytest.MonkeyPatch) -> Server:
    found = Server()
    monkeypatch.setattr(websocket, "tokens", found.tokens)
    return found


@pytest.fixture
def logged_in(credentials: Credentials) -> ClientConfig:
    config = ClientConfig(SERVER, transport="websocket", identity=str(credentials.key))
    write_config(config_path(), config)
    return config


def minted(out: str) -> str:
    return re.search(r"--token (\S+)", out)[1]  # type: ignore[index]


async def checks(credentials: Credentials, token: str) -> bool:
    auth = TokenAuth(TokenSettings(signers=credentials.public_key))
    return await auth.authenticate(TokenCredential(token), Peer("192.0.2.1", 1)) is not None


def test_mints_a_token_the_server_accepts(
    logged_in: ClientConfig, credentials: Credentials, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["tokens", "new", "alice", "--names", "alice,*.alice", "--yes"]) == 0
    out = capsys.readouterr().out
    grant = tokens.decode(minted(out))[0]
    assert grant.names == ("alice", "*.alice")
    assert grant.expires == pytest.approx(time.time() + 7 * 86400, abs=5)
    assert out == (
        f"token for alice, valid until {when(grant.expires)}, for: alice, *.alice\n"
        f"id: {grant.id} (`wildburrow tokens deny {grant.id}` stops it early)\n"
        "\non alice's device:\n"
        "  uv tool install wildburrow\n"
        f"  wildburrow login {SERVER} --auth token --token {minted(out)}\n"
    )
    assert asyncio.run(checks(credentials, minted(out)))


@pytest.mark.parametrize(
    ("expires", "seconds"), [("30m", 1800), ("12h", 43200), ("2d", 172800), ("1w", 604800), (" 3D ", 259200)]
)
def test_expiry_units(logged_in: ClientConfig, capsys: pytest.CaptureFixture[str], expires: str, seconds: int) -> None:
    assert cli.main(["tokens", "new", "a", "--names", "any", "--expires", expires, "-y"]) == 0
    grant = tokens.decode(minted(capsys.readouterr().out))[0]
    assert grant.expires == pytest.approx(time.time() + seconds, abs=5)


def test_a_token_that_never_expires(logged_in: ClientConfig, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tokens", "new", "a", "--names", "any", "--expires", "NEVER", "-y"]) == 0
    out = capsys.readouterr().out
    assert tokens.decode(minted(out))[0].expires is None
    assert out.startswith("token for a, valid until never, for: any name\n")


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "pass --names: the names a may claim, or any"),
        (["--names", " , "], "--names: no names given: pass the names it may claim, or any"),
        (["--names", "bad_label"], "--names: 'bad_label': labels are 1-63 of a-z, 0-9 and '-', or '*' for any one"),
        (["--names", "any", "--expires", "7"], "--expires: expected a count and one of m, h, d, w (like 7d or 12h)"),
        (["--names", "any", "--expires", "0d"], "--expires: expected a count"),
        (["--names", "any", "--expires", "1y"], "--expires: expected a count"),
    ],
)
def test_minting_refuses_what_it_cannot_sign(
    logged_in: ClientConfig, capsys: pytest.CaptureFixture[str], args: list[str], message: str
) -> None:
    assert cli.main(["tokens", "new", "a", *args, "-y"]) == 2
    assert capsys.readouterr().err.startswith(message)
    assert not tokens_cli.log_path().exists()


def test_asks_before_minting(logged_in: ClientConfig, typed: Typist, capsys: pytest.CaptureFixture[str]) -> None:
    typed("y", ENTER)
    assert cli.main(["tokens", "new", "alice", "--names", "alice"]) == 0
    out = capsys.readouterr().out
    grant = tokens.decode(minted(out))[0]
    assert out.startswith(
        f"alice gets a token for alice until {when(grant.expires)}.\n"
        "Only an admin denying it, or its name, stops it sooner.\n"
    )
    assert typed.showed("? Mint it? Yes")


def test_warns_harder_about_a_token_that_never_expires(
    logged_in: ClientConfig, typed: Typist, capsys: pytest.CaptureFixture[str]
) -> None:
    typed("n", ENTER)
    assert cli.main(["tokens", "new", "alice", "--names", "alice", "--expires", "never"]) == 1
    assert capsys.readouterr().out == (
        "alice gets a token for alice that never expires.\nOnly an admin denying it, or its name, stops it sooner.\n"
    )
    assert not tokens_cli.log_path().exists()


def test_declining_is_the_default(logged_in: ClientConfig, typed: Typist) -> None:
    typed(ENTER)
    assert cli.main(["tokens", "new", "alice", "--names", "alice"]) == 1
    assert typed.showed("? Mint it? No")
    assert not tokens_cli.log_path().exists()


def test_without_a_terminal_it_needs_yes(
    logged_in: ClientConfig, no_terminal: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["tokens", "new", "alice", "--names", "alice"]) == 2
    assert capsys.readouterr().err == (
        "pass --yes to mint a token without being asked; only a denial stops it once it's out\n"
    )


def test_server_and_key_can_be_given(
    credentials: Credentials, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = [
        "tokens",
        "new",
        "a",
        "--names",
        "any",
        "-y",
        "--server",
        "other.example.com",
        "--identity",
        str(credentials.key),
        "--offline",
    ]
    assert cli.main(args) == 0
    assert "  wildburrow login other.example.com --auth token --token " in capsys.readouterr().out


def test_without_a_server_it_says_where_the_name_goes(
    credentials: Credentials, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["tokens", "new", "a", "--names", "any", "-y", "--identity", str(credentials.key), "--offline"]
    assert cli.main(args) == 0
    out, err = capsys.readouterr()
    assert "  wildburrow login SERVER --auth token --token " in out
    assert err == "\nno saved login to name the server: replace SERVER, or pass --server\n"
    entry = json.loads(tokens_cli.log_path().read_text())
    # With no server to register it with, nothing will ever say it waits to be.
    assert (entry["server"], entry["registered"], tokens_cli.unsynced()) == ("", None, [])


def test_the_log_lives_in_the_state_directory(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert tokens_cli.log_path() == home / "state" / "wildburrow" / "tokens.jsonl"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert tokens_cli.log_path() == home / ".local" / "state" / "wildburrow" / "tokens.jsonl"


def test_a_token_is_expired_from_its_expiry_on(
    logged_in: ClientConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["tokens", "new", "alice", "--names", "alice", "-y"])
    expires = json.loads(tokens_cli.log_path().read_text())["expires"]
    capsys.readouterr()
    for now, state in [(expires - 1, when(expires)), (expires, f"expired {when(expires)}")]:
        monkeypatch.setattr(time, "time", lambda now=now: now)
        cli.main(["tokens"])
        assert state in capsys.readouterr().out


def test_signing_failures_are_reported(
    logged_in: ClientConfig, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["tokens", "new", "a", "--names", "any", "-y", "--identity", str(tmp_path / "missing")]) == 1
    assert capsys.readouterr().err.startswith("ssh-keygen could not sign: ")


def test_without_any_key_it_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tokens", "new", "a", "--names", "any", "-y"]) == 1
    assert capsys.readouterr().err == "no SSH key found; set one with `wildburrow login --identity PATH`\n"


def test_hashed_tokens_still_mint(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tokens", "new", "ci", "--hash"]) == 0
    token_line, server_line = capsys.readouterr().out.splitlines()
    token = token_line.removeprefix("token (give this to the client): ")
    assert server_line == f"server line (add to {PREFIX}AUTH_TOKEN_HASHES): ci:{tokens.digest(token)}"


def test_every_mint_is_logged_privately_without_the_token(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["tokens", "new", "alice", "--names", "alice", "-y"])
    cli.main(["tokens", "new", "bob", "--names", "any", "--expires", "never", "-y", "--server", "b.example.com"])
    out = capsys.readouterr().out
    # Each is registered with the server it's for, through the saved login.
    assert [call[0] for call in server.calls] == [SERVER, "b.example.com"]
    path = tokens_cli.log_path()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    assert [(e["name"], e["names"], e["server"], e["registered"]) for e in entries] == [
        ("alice", ["alice"], SERVER, True),
        ("bob", None, "b.example.com", True),
    ]
    assert entries[0]["issued"] == pytest.approx(time.time(), abs=5)
    assert entries[1]["expires"] is None
    assert all(minted_token not in path.read_text() for minted_token in re.findall(r"--token (\S+)", out))


def test_tokens_lists_what_was_minted_here(logged_in: ClientConfig, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tokens"]) == 0
    assert capsys.readouterr().out == "no tokens\n"
    cli.main(["tokens", "new", "alice", "--names", "alice,*.alice", "-y"])
    cli.main(["tokens", "new", "bob", "--names", "any", "--expires", "never", "-y", "--offline"])
    log = tokens_cli.log_path()
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    # As minted before 0.8.0: no issued, and not known to be registered or not.
    old = {key: entries[0][key] for key in ("names", "server")}
    entries.append(old | {"id": "0" * 16, "name": "carol", "expires": 1_000_000_000, "server": ""})
    log.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
    capsys.readouterr()
    logged_in_server_only = cli.main(["--no-input", "tokens"])
    assert logged_in_server_only == 0
    first = entries[0]
    assert capsys.readouterr().out.splitlines() == [
        f"{'ID':<16}  NAME   NAMES           EXPIRES{' ' * 23}LAST USED  STATE  SERVER",
        f"{first['id']}  alice  alice, *.alice  {when(first['expires']):<30}-          -      {SERVER}",
        f"{entries[1]['id']}  bob    any name        {'never':<30}-          -      {SERVER}",
        f"{'0' * 16}  carol  alice, *.alice  expired 2001-09-09 01:46 UTC  -          -      -",
    ]


def test_tokens_merges_what_the_server_has_with_what_was_minted_here(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["tokens", "new", "alice", "--names", "alice", "--expires", "never", "-y", "--offline"])
    [mine] = [json.loads(line) for line in tokens_cli.log_path().read_text().splitlines()]
    used = {"name": "dave", "names": ["dave"], "expires": None, "first_used": 5, "last_used": 1_000_000_000}
    server.listed = [
        {"id": "a" * 16, **used, "issued": 1, "denied": None},
        {"id": "b" * 16, **used, "issued": 1, "denied": 7},
        {"id": "c" * 16, **used, "issued": 9, "denied": None},
        {"id": "d" * 16, **used, "issued": None, "denied": None},
        {"id": "g" * 16, **used, "issued": 5, "denied": None},
        {"id": "e" * 16, "name": None, "names": None, "expires": None, "issued": None, "first_used": None,
         "last_used": None, "denied": 3},
        {"id": mine["id"], "name": None, "names": None, "expires": None, "issued": mine["issued"],
         "first_used": 5, "last_used": 1_000_000_000, "denied": None},
    ]  # fmt: skip
    server.denied_names = {"dave": 5}
    with tokens_cli.log_path().open("a") as log:
        other = {"id": "f" * 16, "name": "dave", "names": ["dave"], "expires": None, "issued": 1}
        log.write(json.dumps(other | {"server": "b.example.com", "registered": True}) + "\n")
    capsys.readouterr()
    assert cli.main(["tokens"]) == 0
    # The offline mint was registered on the way.
    assert server.calls[-1] == (SERVER, [mine["id"]], True)
    last = when(1_000_000_000)
    assert capsys.readouterr().out.splitlines() == [
        f"{'ID':<16}  NAME   NAMES     EXPIRES  {'LAST USED':<20}  STATE   SERVER",
        f"{'a' * 16}  dave   dave      never    {last}  denied  {SERVER}",
        f"{'b' * 16}  dave   dave      never    {last}  denied  {SERVER}",
        f"{'c' * 16}  dave   dave      never    {last}  -       {SERVER}",
        f"{'d' * 16}  dave   dave      never    {last}  -       {SERVER}",
        f"{'g' * 16}  dave   dave      never    {last}  -       {SERVER}",
        f"{'e' * 16}  -      any name  never    {'-':<20}  denied  {SERVER}",
        f"{mine['id']}  alice  alice     never    {last}  -       {SERVER}",
        f"{'f' * 16}  dave   dave      never    {'-':<20}  -       b.example.com",
        "denied: every token for dave minted before 1970-01-01 00:00 UTC",
    ]
    assert json.loads(tokens_cli.log_path().read_text().splitlines()[0])["registered"] is True


@pytest.mark.parametrize(
    ("error", "said"),
    [("only an admin can list tokens", "only an admin can list tokens"),
     (websocket.ClientError("could not connect"), "could not connect")],
)  # fmt: skip
def test_tokens_lists_this_machines_alone_when_the_server_wont(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], error: Any, said: str
) -> None:
    cli.main(["tokens", "new", "alice", "--names", "alice", "-y", "--offline"])
    server.error = error
    capsys.readouterr()
    assert cli.main(["tokens"]) == 0
    out, err = capsys.readouterr()
    assert out.splitlines()[1].endswith(f"unregistered  {SERVER}")
    assert err == f"couldn't list {SERVER}'s tokens: {said}; listing this machine's\n"


def test_minting_registers_the_token_first(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    server.memory = True
    assert cli.main(["tokens", "new", "alice", "--names", "alice", "-y"]) == 0
    out, err = capsys.readouterr()
    grant = tokens.decode(minted(out))[0]
    assert server.calls == [(SERVER, [grant.id], False)]
    assert err == f"{SERVER} keeps its record in memory, so it forgets registered tokens on restart\n"


@pytest.mark.parametrize(
    ("error", "said"),
    [("only an admin can register tokens", "only an admin can register tokens"),
     (websocket.ClientError(f"{SERVER} runs an older wildburrow; this needs 0.8.0 or later"),
      f"{SERVER} runs an older wildburrow; this needs 0.8.0 or later")],
)  # fmt: skip
def test_a_token_that_cant_be_registered_isnt_minted_without_a_terminal(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], error: Any, said: str
) -> None:
    server.error = error
    assert cli.main(["tokens", "new", "alice", "--names", "alice", "-y"]) == 2
    out, err = capsys.readouterr()
    assert (out, err) == ("", f"couldn't register the token with {SERVER}: {said}; pass --offline\n")
    assert not tokens_cli.log_path().exists()


def test_without_a_login_a_token_cant_be_registered(
    credentials: Credentials, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["tokens", "new", "a", "--names", "any", "-y", "--identity", str(credentials.key)]
    assert cli.main([*args, "--server", "other.example.com"]) == 2
    assert capsys.readouterr().err == (
        "couldn't register the token with other.example.com: no saved login to reach a server with; pass --offline\n"
    )
    assert cli.main(args) == 2
    assert capsys.readouterr().err == (
        "couldn't register the token with a server: no saved login to reach a server with; pass --offline\n"
    )


@pytest.mark.parametrize(("answer", "code"), [("y", 0), ("n", 1), (ENTER, 1)])
def test_in_a_terminal_it_asks_whether_to_mint_it_unregistered(
    logged_in: ClientConfig, server: Server, typed: Typist, capsys: pytest.CaptureFixture[str], answer: str,
    code: int,
) -> None:  # fmt: skip
    server.error = "only an admin can register tokens"
    typed(*([answer, ENTER] if answer != ENTER else [ENTER]))
    assert cli.main(["tokens", "new", "alice", "--names", "alice", "-y"]) == code
    out = capsys.readouterr().out
    assert out.startswith(f"Couldn't register the token with {SERVER}: only an admin can register tokens\n")
    assert ("--token" in out) == (code == 0)
    if code == 0:
        assert json.loads(tokens_cli.log_path().read_text())["registered"] is False
    else:
        assert not tokens_cli.log_path().exists()


def test_offline_doesnt_try_the_server(logged_in: ClientConfig, server: Server) -> None:
    assert cli.main(["tokens", "new", "alice", "--names", "alice", "-y", "--offline"]) == 0
    assert server.calls == []
    assert json.loads(tokens_cli.log_path().read_text())["registered"] is False


def test_sync_registers_what_was_minted_offline(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["tokens", "sync"]) == 0
    assert capsys.readouterr().out == f"every token minted here for {SERVER} is registered\n"
    for name in ("a", "b"):
        cli.main(["tokens", "new", name, "--names", "any", "-y", "--offline"])
    cli.main(["tokens", "new", "c", "--names", "any", "-y", "--offline", "--server", "other.example.com"])
    ids = [json.loads(line)["id"] for line in tokens_cli.log_path().read_text().splitlines()]
    capsys.readouterr()
    server.error, server.partial = "only an admin can register tokens", 1
    assert cli.main(["tokens", "sync"]) == 1
    assert capsys.readouterr() == (
        f"registered 1 of 2 with {SERVER}\n",
        f"couldn't register with {SERVER}: only an admin can register tokens\n",
    )
    server.error = None
    assert cli.main(["tokens", "sync"]) == 0
    assert capsys.readouterr().out == f"registered 1 of 1 with {SERVER}\n"
    assert server.calls[-1] == (SERVER, ids[1:2], False)
    assert [entry["id"] for entry in tokens_cli.unsynced()] == ids[2:]
    assert stat.S_IMODE(tokens_cli.log_path().stat().st_mode) == 0o600
    # Listing registers only what's for the saved login's server.
    cli.main(["tokens"])
    assert server.calls[-1] == (SERVER, [], True)


def test_sync_needs_a_login(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tokens", "sync"]) == 2
    assert capsys.readouterr().err == "no saved login to reach a server with: run `wildburrow login` first\n"


def test_other_commands_say_when_tokens_wait_to_be_registered(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    sync = "; run: wildburrow tokens sync (or: wildburrow config set sync-notice off)\n"
    cli.main(["tokens", "new", "a", "--names", "any", "-y", "--offline"])
    capsys.readouterr()
    cli.main(["config"])
    assert capsys.readouterr().err == f"1 token minted with --offline isn't registered with {SERVER}{sync}"
    cli.main(["tokens", "new", "b", "--names", "any", "-y", "--offline"])
    # `tokens` itself says nothing of it, registering them instead.
    assert capsys.readouterr().err == ""
    with tokens_cli.log_path().open("a") as log:
        log.write(json.dumps({"id": "0" * 16, "server": "b.example.com", "registered": False}) + "\n")
    cli.main(["config"])
    assert capsys.readouterr().err == (
        f"2 tokens minted with --offline aren't registered with {SERVER}{sync}"
        f"1 token minted with --offline isn't registered with b.example.com{sync}"
    )
    assert cli.main(["config", "set", "sync-notice", "off"]) == 0
    capsys.readouterr()
    cli.main(["config"])
    assert capsys.readouterr().err == ""


def test_names_lists_what_the_server_has_bound(
    logged_in: ClientConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    asked: list[ClientConfig] = []

    async def held(config: ClientConfig, ask: object) -> list[dict]:
        assert ask is cli_ask.password
        asked.append(config)
        return [{"name": "pic", "yours": False}, {"name": "*.mine", "yours": True}, {"name": "mine", "yours": True}]

    monkeypatch.setattr(websocket, "held_names", held)
    monkeypatch.setenv(client_cli.TOKEN_ENV, "from-env")
    assert cli.main(["names"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "NAME    HOLDER",
        "*.mine  you",
        "mine    you",
        "pic     someone else",
    ]
    assert asked == [logged_in.__replace__(token="from-env", **client_cli.BY_TOKEN)]
    assert cli.main(["names", "--server", "other.example.com"]) == 0
    assert asked[-1].server == "other.example.com"


def test_names_when_nothing_is_bound(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    async def held(config: ClientConfig, ask: object) -> list[dict]:
        assert config == ClientConfig("other.example.com")
        return []

    monkeypatch.setattr(websocket, "held_names", held)
    assert cli.main(["names", "--server", "other.example.com"]) == 0
    assert capsys.readouterr().out == "no names are bound\n"


def test_names_needs_a_server(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["names"]) == 2
    assert capsys.readouterr().err == "no server configured: run `wildburrow login` or pass --server\n"


def test_names_reports_why_it_could_not_ask(
    logged_in: ClientConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def held(config: ClientConfig, ask: object) -> list[dict]:
        raise websocket.ClientError("authentication failed")

    monkeypatch.setattr(websocket, "held_names", held)
    assert cli.main(["names"]) == 1
    assert capsys.readouterr().err == "authentication failed\n"


def test_expiry_is_shown_in_utc_whatever_the_local_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    time.tzset()
    try:
        assert when(1_000_000_000) == "2001-09-09 01:46 UTC"
    finally:
        monkeypatch.undo()
        time.tzset()


def test_minting_needs_a_name_without_a_terminal(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tokens", "new"]) == 2
    assert capsys.readouterr().err.splitlines()[-1] == "Error: Missing argument 'NAME'."


@pytest.mark.parametrize(
    ("answer", "code", "out", "err"),
    [
        ({"tokens": ["a", "b"], "ended": []}, 0, "denied a\ndenied b\n", ""),
        ({"tokens": ["a"], "ended": ["s1", "s2"]}, 0, "denied a\nended 2 of their sessions\n", ""),
        ({"error": "only an admin can deny tokens"}, 1, "", "only an admin can deny tokens\n"),
    ],
)
def test_deny_says_what_it_did(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], answer: dict, code: int, out: str, err: str
) -> None:
    asked: list[tuple[str, list[str]]] = []

    async def deny(config: ClientConfig, ids: list[str], ask: object, names: tuple[str, ...] = ()) -> dict:
        asked.append((config.server, list(ids)))
        return answer

    write_config(config_path(), ClientConfig("s.example.com", transport="websocket", auth="token", token="t"))
    monkeypatch.setattr(websocket, "deny", deny)
    assert cli.main(["tokens", "deny", "a", "b"]) == code
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (out, err)
    assert asked == [("s.example.com", ["a", "b"])]


def test_deny_by_name_says_from_when_and_warns_of_memory(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    asked: list[tuple[list[str], tuple[str, ...]]] = []
    answer = {"tokens": ["a"], "ended": [], "names": ["bob", "carol"], "before": 1_000_000_000, "memory": True}

    async def deny(config: ClientConfig, ids: list[str], ask: object, names: tuple[str, ...] = ()) -> dict:
        asked.append((list(ids), names))
        return answer

    write_config(config_path(), ClientConfig("s.example.com", transport="websocket"))
    monkeypatch.setattr(websocket, "deny", deny)
    assert cli.main(["tokens", "deny", "a", "--name", "bob", "--name", "carol"]) == 0
    assert asked == [(["a"], ("bob", "carol"))]
    out, err = capsys.readouterr()
    before = when(1_000_000_000)
    assert out == (
        f"denied a\ndenied every token for bob minted before {before}; mint new ones after that\n"
        f"denied every token for carol minted before {before}; mint new ones after that\n"
    )
    assert err == "the server keeps its record in memory, so it forgets the denial on restart\n"
    assert cli.main(["tokens", "deny"]) == 2
    assert capsys.readouterr().err == "name the tokens to deny: their IDs, or --name NAME\n"
    assert len(asked) == 1


@pytest.mark.parametrize(("value", "shown"), [("off", False), ("no", False), ("yes", True), ("maybe", True)])
def test_the_sync_notice_can_be_turned_off_by_variable(
    logged_in: ClientConfig, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], value: str,
    shown: bool,
) -> None:  # fmt: skip
    cli.main(["tokens", "new", "a", "--names", "any", "-y", "--offline"])
    capsys.readouterr()
    monkeypatch.setenv("WILDBURROW_CLIENT_SYNC_NOTICE", value)
    cli.main(["config"])
    assert bool(capsys.readouterr().err) == shown


def test_without_a_login_tokens_lists_this_machines(
    credentials: Credentials, server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["tokens", "new", "a", "--names", "any", "-y", "--identity", str(credentials.key), "--offline"]
    assert cli.main([*args, "--server", "other.example.com"]) == 0
    capsys.readouterr()
    assert cli.main(["tokens"]) == 0
    out, err = capsys.readouterr()
    assert out.splitlines()[1].endswith("unregistered  other.example.com")
    assert (err, server.calls) == ("", [])


@pytest.mark.parametrize(
    ("error", "said"),
    [("only an admin can register tokens", "only an admin can register tokens"),
     (websocket.ClientError("could not connect"), "could not connect")],
)  # fmt: skip
def test_sync_refused_outright_registers_nothing(
    logged_in: ClientConfig, server: Server, capsys: pytest.CaptureFixture[str], error: Any, said: str
) -> None:
    cli.main(["tokens", "new", "a", "--names", "any", "-y", "--offline"])
    capsys.readouterr()
    server.error = error
    assert cli.main(["tokens", "sync"]) == 1
    assert capsys.readouterr() == ("", f"couldn't register with {SERVER}: {said}\n")
    assert len(tokens_cli.unsynced()) == 1


def test_in_a_terminal_without_a_login_it_asks_too(
    credentials: Credentials, typed: Typist, capsys: pytest.CaptureFixture[str]
) -> None:
    typed("y", ENTER)
    assert cli.main(["tokens", "new", "a", "--names", "any", "-y", "--identity", str(credentials.key)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Couldn't register the token with a server: no saved login to reach a server with\n")
    assert typed.showed("? Mint it without registering it? Yes")
