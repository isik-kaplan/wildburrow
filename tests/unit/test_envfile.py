import stat
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from wildburrow import envfile

keys = st.from_regex(r"[A-Z_][A-Z0-9_]{0,20}", fullmatch=True)
LINE_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
values = st.text(st.characters(exclude_categories=["Cs"]))


@given(st.dictionaries(keys, values))
def test_values_read_back_unchanged_or_are_refused(settings: dict[str, str]) -> None:
    single = {key: value for key, value in settings.items() if not any(char in LINE_BREAKS for char in value)}
    text = "".join(f"{key}={envfile.quote(value)}\n" for key, value in single.items())
    assert envfile.parse(text) == single
    for value in settings.values():
        if value not in single.values():
            with pytest.raises(ValueError, match=r"^an environment file value can't span lines$"):
                envfile.quote(value)


@pytest.mark.parametrize(
    ("value", "quoted"),
    [
        ("plain", '"plain"'),
        ('say "hi"', '"say \\"hi\\""'),
        ("back\\slash", '"back\\\\slash"'),
        ("$HOME and `cmd`", '"\\$HOME and \\`cmd\\`"'),
        ("", '""'),
    ],
)
def test_quoting_escapes_what_systemd_unescapes(value: str, quoted: str) -> None:
    assert envfile.quote(value) == quoted


@pytest.mark.parametrize("value", ["one\ntwo", "a\rb", "x\u2028", "\n"])
def test_values_cannot_span_lines(value: str) -> None:
    with pytest.raises(ValueError, match=r"^an environment file value can't span lines$"):
        envfile.quote(value)


def test_parse_reads_bare_and_quoted_values() -> None:
    text = '# comment\n\n  A = spaced  \nB="quoted \\"x\\""\nC=\nD="\nE=a=b\nF="lone \\x"\n'
    assert envfile.parse(text) == {"A": "spaced", "B": 'quoted "x"', "C": "", "D": '"', "E": "a=b", "F": "lone x"}


@pytest.mark.parametrize(
    ("raw", "value"),
    [
        ('"open', '"open'),
        ('shut"', 'shut"'),
        ('"\\$HOME"', "$HOME"),
        ('"a\\\\b"', "a\\b"),
        ('"\\\\\\""', '\\"'),
        ('"x\\\\"', "x\\"),
    ],
)
def test_parse_unescapes_like_systemd(raw: str, value: str) -> None:
    assert envfile.parse(f"K={raw}\n") == {"K": value}


@pytest.mark.parametrize(("text", "line"), [("A=1\nnothing here\n", 2), ("=value\n", 1), ("  =x", 1)])
def test_lines_need_a_key(text: str, line: int) -> None:
    with pytest.raises(envfile.EnvFileError, match=rf"^line {line}: expected KEY=VALUE$"):
        envfile.parse(text)


def test_write_then_read(tmp_path: Path) -> None:
    path = tmp_path / "env"
    envfile.write(path, {"A": "1", "B": 'two "words"'}, 0o600)
    assert path.read_text() == 'A="1"\nB="two \\"words\\""\n'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert envfile.read(path) == {"A": "1", "B": 'two "words"'}


def test_write_creates_the_file_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    modes: list[int] = []
    monkeypatch.setattr(Path, "chmod", lambda self, mode: modes.append(stat.S_IMODE(self.stat().st_mode)))
    envfile.write(tmp_path / "env", {"A": "1"}, 0o600)
    assert modes == [0o600]


def test_write_tightens_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "env"
    path.write_text("old")
    path.chmod(0o644)
    envfile.write(path, {}, 0o600)
    assert path.read_text() == ""
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_read_names_the_file(tmp_path: Path) -> None:
    path = tmp_path / "env"
    path.write_text("bad\n")
    with pytest.raises(envfile.EnvFileError, match=rf"^{path}: line 1: expected KEY=VALUE$"):
        envfile.read(path)
    with pytest.raises(envfile.EnvFileError, match=r"No such file or directory"):
        envfile.read(tmp_path / "missing")
