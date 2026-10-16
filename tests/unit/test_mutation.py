import json
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import mutation, mutation_killers

PYPROJECT = """
[tool.mutmut]
source_paths = ["src/pkg"]

[tool.pytest.ini_options]
addopts = "-q"
"""
TEST_MODULE = """
import pytest

LIMIT = 3


def helper():
    return LIMIT


def test_one():
    assert helper() == 3


class TestGroup:
    def test_two(self):
        assert True
"""
ONE = "tests/test_mod.py::test_one"
TWO = "tests/test_mod.py::TestGroup::test_two"
OTHER = "tests/test_other.py::test_other[1]"
FUNCTION = "pkg.mod.xǁfunction"


def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    write(tmp_path, "pyproject.toml", PYPROJECT)
    for name in mutation.TOOLING:
        write(tmp_path, name, name)
    write(tmp_path, "src/pkg/mod.py", "def function():\n    return 1\n")
    write(tmp_path, "tests/test_mod.py", TEST_MODULE)
    write(tmp_path, "tests/test_other.py", "def test_other():\n    pass\n")
    write(tmp_path, "tests/conftest.py", "")
    write(tmp_path, "tests/support.py", "")
    write(tmp_path, "tests/__pycache__/x.pyc", "ignored")
    return tmp_path


def stats(**traced: list[str]) -> dict:
    tests = {test for names in traced.values() for test in names}
    return {
        "tests_by_mangled_function_name": {function.replace("_", "."): names for function, names in traced.items()},
        "duration_by_test": dict.fromkeys(sorted(tests), 0.1),
    }


def test_the_cache_key_follows_settings_and_tooling_but_not_formatting(root: Path) -> None:
    key = mutation.cache_key(root)
    write(root, "pyproject.toml", "# a comment\n" + PYPROJECT)
    assert mutation.cache_key(root) == key
    write(root, "pyproject.toml", PYPROJECT.replace("src/pkg", "src"))
    assert mutation.cache_key(root) != key
    write(root, "pyproject.toml", PYPROJECT)
    write(root, "uv.lock", "changed")
    assert mutation.cache_key(root) != key


def test_test_modules_are_hashed_per_test(root: Path) -> None:
    hashes = mutation.file_hashes(root)
    assert set(hashes) == {
        "src/pkg/mod.py",
        "tests/conftest.py",
        "tests/support.py",
        "tests/test_mod.py",
        "tests/test_mod.py::test_one",
        "tests/test_mod.py::TestGroup",
        "tests/test_other.py",
        "tests/test_other.py::test_other",
    }
    write(root, "tests/test_mod.py", TEST_MODULE.replace("def test_one():", "# moved\n\n\ndef test_one():"))
    assert mutation.file_hashes(root) == hashes
    write(root, "tests/test_mod.py", TEST_MODULE.replace("== 3", "== 4"))
    assert mutation.changed_between(hashes, mutation.file_hashes(root)) == {ONE.partition("[")[0]}


def test_nothing_is_changed_without_a_cache(root: Path) -> None:
    assert mutation.changed_files(root, mutation.file_hashes(root)) == set()


def test_a_cache_without_a_baseline_is_entirely_changed(root: Path) -> None:
    write(root, f"{mutation.TREE}/{mutation.STATS}", "{}")
    current = mutation.file_hashes(root)
    assert mutation.changed_files(root, current) == set(current)


def test_changes_are_read_against_the_baseline(root: Path) -> None:
    current = mutation.file_hashes(root)
    write(root, f"{mutation.TREE}/{mutation.BASELINE}", json.dumps({**current, "tests/gone.py": "x"}))
    current["tests/support.py"] = "different"
    assert mutation.changed_files(root, current) == {"tests/gone.py", "tests/support.py"}


@pytest.mark.parametrize(
    ("changed", "sources", "expected"),
    [
        ({"tests/test_mod.py::test_one"}, False, {ONE}),
        ({"tests/test_mod.py::TestGroup"}, False, {TWO}),
        ({"tests/test_mod.py"}, False, {ONE, TWO}),
        ({"tests/test_other.py::test_other"}, False, {OTHER}),
        ({"tests/conftest.py"}, False, {ONE, TWO, OTHER}),
        ({"tests/e2e/conftest.py"}, False, set()),
        ({"tests/support.py"}, False, None),
        ({"src/pkg/mod.py"}, False, set()),
        ({"src/pkg/mod.py"}, True, {ONE}),
        ({"src/pkg/new.py"}, True, None),
    ],
)
def test_stale_tests(changed: set[str], sources: bool, expected: set[str] | None) -> None:
    traced = stats(pkg_mod_xǁfunction=[ONE], pkg_other_xǁf=[TWO, OTHER])
    assert mutation.stale_tests(changed, traced, sources) == expected


def mutant(number: int) -> str:
    return f"{FUNCTION}{mutation_killers.MARKER}{number}"


def test_invalidate_clears_what_a_changed_test_decided(root: Path) -> None:
    tree = root / mutation.TREE
    mutation.invalidate(root)
    write(root, f"{mutation.TREE}/{mutation.STATS}", json.dumps(stats(**{FUNCTION: [ONE, TWO]})))
    verdicts = {mutant(1): 1, mutant(2): 1, mutant(3): 3, mutant(4): 0, mutant(5): 37, mutant(6): None}
    meta = write(root, f"{mutation.TREE}/src/pkg/mod.py.meta", json.dumps({"exit_code_by_key": verdicts}))
    write(root, f"{mutation.TREE}/src/pkg/settled.py.meta", json.dumps({"exit_code_by_key": {"settled": 37}}))
    record = [{"mutant": mutant(1), "killer": TWO}, {"mutant": mutant(2), "killer": ONE}]
    write(root, f"{mutation.TREE}/{mutation_killers.RECORD}", "\n".join(json.dumps(line) for line in record) + "\n")
    write(root, "tests/test_mod.py", TEST_MODULE.replace("== 3", "== 4"))

    assert mutation.invalidate(root) == {"changed": 1, "verdicts": 3, "traces": 1}
    assert json.loads(meta.read_text())["exit_code_by_key"] == {
        mutant(1): 1,
        mutant(2): None,
        mutant(3): None,
        mutant(4): None,
        mutant(5): 37,
        mutant(6): None,
    }
    assert json.loads((tree / mutation.STATS).read_text()) == stats(**{FUNCTION: [TWO]})
    assert mutation.invalidate(root) == {"changed": 0, "verdicts": 0, "traces": 0}
    write(root, "tests/e2e/conftest.py", "")
    assert mutation.invalidate(root) == {"changed": 1, "verdicts": 0, "traces": 0}


def test_an_untraceable_change_clears_everything(root: Path) -> None:
    mutation.invalidate(root)
    write(root, f"{mutation.TREE}/{mutation.STATS}", json.dumps(stats(**{FUNCTION: [ONE]})))
    meta = write(root, f"{mutation.TREE}/src/pkg/mod.py.meta", json.dumps({"exit_code_by_key": {mutant(1): 1}}))
    write(root, "tests/support.py", "CHANGED = True\n")
    assert mutation.invalidate(root) == {"changed": 1, "verdicts": 1, "traces": 1}
    assert json.loads(meta.read_text())["exit_code_by_key"] == {mutant(1): None}
    assert json.loads((root / mutation.TREE / mutation.STATS).read_text()) == {
        "tests_by_mangled_function_name": {FUNCTION: []},
        "duration_by_test": {},
    }


def test_prune_drops_copies_of_removed_files(root: Path) -> None:
    kept = [
        write(root, f"{mutation.TREE}/src/pkg/mod.py", ""),
        write(root, f"{mutation.TREE}/src/pkg/mod.py.meta", ""),
        write(root, f"{mutation.TREE}/src/pkg/mod.py.spans", ""),
        write(root, f"{mutation.TREE}/tests/__pycache__/gone.pyc", ""),
        write(root, f"{mutation.TREE}/{mutation.STATS}", ""),
    ]
    gone = [
        write(root, f"{mutation.TREE}/src/pkg/gone.py", ""),
        write(root, f"{mutation.TREE}/src/pkg/gone.py.meta", ""),
        write(root, f"{mutation.TREE}/src/pkg/gone.py.spans", ""),
        write(root, f"{mutation.TREE}/tests/test_gone.py", ""),
        write(root, f"{mutation.TREE}/scripts/gone.py", ""),
    ]
    assert mutation.prune(root) == len(gone)
    assert all(path.exists() for path in kept)
    assert not any(path.exists() for path in gone)


class FakeMutmut:
    def __init__(self, root: Path, counts: dict[str, int]) -> None:
        self.root = root
        self.counts = counts
        self.calls: list[tuple[list[str], dict | None]] = []
        self.verdicts: dict[str, int | None] | None = None

    def __call__(self, command: list[str], cwd: Path, env: dict | None, check: bool) -> None:
        assert cwd == self.root
        self.calls.append((command[3:], env))
        if self.verdicts is not None and command[3] == "run":
            write(self.root, f"{mutation.TREE}/src/pkg/mod.py.meta", json.dumps({"exit_code_by_key": self.verdicts}))
        if command[3] == "export-cicd-stats":
            write(self.root, f"{mutation.TREE}/{mutation.CICD_STATS}", json.dumps(self.counts))


@pytest.fixture
def fake_mutmut(root: Path, monkeypatch: pytest.MonkeyPatch):
    def install(counts: dict[str, int]) -> FakeMutmut:
        fake = FakeMutmut(root, counts)
        monkeypatch.setattr(subprocess, "run", fake)
        return fake

    return install


@pytest.mark.parametrize(
    ("counts", "status"),
    [
        ({"killed": 3, "timeout": 0, "total": 3}, 0),
        ({"killed": 2, "timeout": 1, "total": 3}, 0),
        ({"killed": 2, "timeout": 0, "total": 3}, 1),
        ({"killed": 0, "timeout": 0, "total": 0}, 1),
    ],
)
def test_check_needs_every_mutant_killed(
    root: Path, fake_mutmut, capsys: pytest.CaptureFixture[str], counts: dict[str, int], status: int
) -> None:
    fake = fake_mutmut(counts)
    write(root, f"{mutation.TREE}/{mutation.CICD_STATS}", json.dumps(counts))
    assert mutation.main(["check"], root) == status
    assert (
        capsys.readouterr().out == f"{counts['killed']} of {counts['total']} mutants killed, {counts['timeout']} hung\n"
    )
    assert [command for command, _ in fake.calls] == ([["results"]] if status else [])


@pytest.mark.parametrize(("platform", "env"), [("darwin", mutation.DARWIN_ENV), ("linux", None)])
def test_run(root: Path, fake_mutmut, monkeypatch: pytest.MonkeyPatch, platform: str, env: dict | None) -> None:
    monkeypatch.setattr(mutation.sys, "platform", platform)
    monkeypatch.setattr(mutation.os, "cpu_count", lambda: 3)
    fake = fake_mutmut({"killed": 1, "timeout": 0, "total": 1})
    stale = write(root, f"{mutation.TREE}/stale", "")
    before = {mutant(1): None, mutant(2): None, mutant(3): None, mutant(4): None, mutant(5): 0}
    write(root, f"{mutation.TREE}/src/pkg/mod.py.meta", json.dumps({"exit_code_by_key": before}))
    fake.verdicts = {mutant(1): 1, mutant(2): 0, mutant(3): 36, mutant(4): 37, mutant(5): 0}
    assert mutation.main(["run"], root) == 0
    assert stale.exists()
    assert [command for command, _ in fake.calls] == [
        ["run", "--max-children", "3"],
        ["run", "--max-children", "1", mutant(2), mutant(3)],
        ["export-cicd-stats"],
    ]
    assert all(passed is None if env is None else env.items() <= passed.items() for _, passed in fake.calls)
    assert (root / mutation.TREE / mutation.BASELINE).exists()
    fake.verdicts = None
    assert mutation.main(["run", "--full"], root) == 0
    assert not stale.exists()
    assert [command for command, _ in fake.calls[3:]] == [["run", "--max-children", "3"], ["export-cicd-stats"]]


def test_key_command(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert mutation.main(["key"], root) == 0
    assert capsys.readouterr().out == mutation.cache_key(root) + "\n"


@pytest.mark.parametrize(
    ("mutant_name", "failed", "recorded"),
    [(mutant(1), True, True), (mutant(1), False, False), ("stats", True, False), ("", True, False)],
)
def test_the_killer_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutant_name: str, failed: bool, recorded: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MUTANT_UNDER_TEST", mutant_name)
    mutation_killers.pytest_runtest_logreport(SimpleNamespace(failed=failed, nodeid=ONE))
    record = tmp_path / mutation_killers.RECORD
    assert mutation.killers(record) == ({mutant_name: ONE} if recorded else {})


def test_runs_as_a_module(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["mutation", "key"])
    monkeypatch.delitem(sys.modules, "scripts.mutation")
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("scripts.mutation", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == mutation.cache_key(mutation.ROOT) + "\n"


@pytest.mark.parametrize(("stale", "expected"), [({OTHER}, False), ({ONE}, True), (None, True)])
def test_a_confirmed_hang_is_settled_like_a_kill(stale: set[str] | None, expected: bool) -> None:
    assert mutation.verdict_is_stale(mutant(1), 36, stale, {FUNCTION: [ONE]}, {}) is expected
