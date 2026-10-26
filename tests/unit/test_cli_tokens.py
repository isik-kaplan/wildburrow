import json
import re
import stat
import time
from pathlib import Path

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


async def test_mints_a_token_the_server_accepts(
    logged_in: ClientConfig, credentials: Credentials, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["tokens", "new", "alice", "--names", "alice,*.alice", "--yes"]) == 0
    out = capsys.readouterr().out
    grant = tokens.decode(minted(out))[0]
    assert grant.names == ("alice", "*.alice")
    assert grant.expires == pytest.approx(time.time() + 7 * 86400, abs=5)
    assert out == (
        f"token for alice, valid until {when(grant.expires)}, for: alice, *.alice\n"
        f"id: {grant.id} (for {PREFIX}AUTH_TOKEN_DENY, should it need stopping early)\n"
        "\non alice's device:\n"
        "  uv tool install wildburrow\n"
        f"  wildburrow login {SERVER} --auth token --token {minted(out)}\n"
    )
    assert await checks(credentials, minted(out))


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
        "It can't be withdrawn before then, short of rotating the signer key.\n"
    )
    assert typed.showed("? Mint it? Yes")


def test_warns_harder_about_a_token_that_never_expires(
    logged_in: ClientConfig, typed: Typist, capsys: pytest.CaptureFixture[str]
) -> None:
    typed("n", ENTER)
    assert cli.main(["tokens", "new", "alice", "--names", "alice", "--expires", "never"]) == 1
    assert capsys.readouterr().out == (
        "alice gets a token for alice that never expires.\n"
        f"Only rotating the signer key or adding its id to {PREFIX}AUTH_TOKEN_DENY will ever stop it.\n"
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
        "pass --yes to mint a token without being asked; it can't be withdrawn once minted\n"
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
    ]
    assert cli.main(args) == 0
    assert "  wildburrow login other.example.com --auth token --token " in capsys.readouterr().out


def test_without_a_server_it_says_where_the_name_goes(
    credentials: Credentials, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["tokens", "new", "a", "--names", "any", "-y", "--identity", str(credentials.key)]) == 0
    out, err = capsys.readouterr()
    assert "  wildburrow login SERVER --auth token --token " in out
    assert err == "\nno saved login to name the server: replace SERVER, or pass --server\n"
    assert json.loads(tokens_cli.log_path().read_text())["server"] == ""


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
    logged_in: ClientConfig, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["tokens", "new", "alice", "--names", "alice", "-y"])
    cli.main(["tokens", "new", "bob", "--names", "any", "--expires", "never", "-y", "--server", "b.example.com"])
    out = capsys.readouterr().out
    path = tokens_cli.log_path()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    assert [(e["name"], e["names"], e["server"]) for e in entries] == [
        ("alice", ["alice"], SERVER),
        ("bob", None, "b.example.com"),
    ]
    assert entries[1]["expires"] is None
    assert all(minted_token not in path.read_text() for minted_token in re.findall(r"--token (\S+)", out))


def test_tokens_lists_what_was_minted_here(logged_in: ClientConfig, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tokens"]) == 0
    assert capsys.readouterr().out == "no tokens minted on this machine\n"
    cli.main(["tokens", "new", "alice", "--names", "alice,*.alice", "-y"])
    cli.main(["tokens", "new", "bob", "--names", "any", "--expires", "never", "-y"])
    log = tokens_cli.log_path()
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    entries.append(entries[0] | {"id": "0" * 16, "name": "carol", "expires": 1_000_000_000, "server": ""})
    log.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
    capsys.readouterr()
    assert cli.main(["tokens"]) == 0
    first = entries[0]
    assert capsys.readouterr().out.splitlines() == [
        f"{'ID':<16}  NAME   NAMES           EXPIRES{' ' * 23}SERVER",
        f"{first['id']}  alice  alice, *.alice  {when(first['expires']):<30}{SERVER}",
        f"{entries[1]['id']}  bob    any name        {'never':<30}{SERVER}",
        f"{'0' * 16}  carol  alice, *.alice  expired 2001-09-09 01:46 UTC  -",
    ]


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

    async def deny(config: ClientConfig, ids: list[str], ask: object) -> dict:
        asked.append((config.server, list(ids)))
        return answer

    write_config(config_path(), ClientConfig("s.example.com", transport="websocket", auth="token", token="t"))
    monkeypatch.setattr(websocket, "deny", deny)
    assert cli.main(["tokens", "deny", "a", "b"]) == code
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (out, err)
    assert asked == [("s.example.com", ["a", "b"])]
