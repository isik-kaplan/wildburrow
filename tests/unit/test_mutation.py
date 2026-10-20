import ast
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
source_paths = ["pkg"]

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
    write(tmp_path, "pkg/mod.py", "def function():\n    return 1\n")
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
    write(root, "pyproject.toml", PYPROJECT.replace("pkg", "lib"))
    assert mutation.cache_key(root) != key
    write(root, "pyproject.toml", PYPROJECT)
    write(root, "uv.lock", "changed")
    assert mutation.cache_key(root) != key


def test_test_modules_are_hashed_per_test(root: Path) -> None:
    hashes = mutation.file_hashes(root)
    assert set(hashes) == {
        "pkg/mod.py",
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
    write(root, f"{mutation.TREE}/{mutation_killers.STATS}", "{}")
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
        ({"pkg/mod.py"}, False, set()),
        ({"pkg/mod.py"}, True, {ONE}),
        ({"pkg/new.py"}, True, None),
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
    write(root, f"{mutation.TREE}/{mutation_killers.STATS}", json.dumps(stats(**{FUNCTION: [ONE, TWO]})))
    verdicts = {mutant(1): 1, mutant(2): 1, mutant(3): 3, mutant(4): 0, mutant(5): 37, mutant(6): None}
    meta = write(root, f"{mutation.TREE}/pkg/mod.py.meta", json.dumps({"exit_code_by_key": verdicts}))
    write(root, f"{mutation.TREE}/pkg/settled.py.meta", json.dumps({"exit_code_by_key": {"settled": 37}}))
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
    assert json.loads((tree / mutation_killers.STATS).read_text()) == stats(**{FUNCTION: [TWO]})
    assert mutation.invalidate(root) == {"changed": 0, "verdicts": 0, "traces": 0}
    write(root, "tests/e2e/conftest.py", "")
    assert mutation.invalidate(root) == {"changed": 1, "verdicts": 0, "traces": 0}


def test_an_untraceable_change_clears_everything(root: Path) -> None:
    mutation.invalidate(root)
    write(root, f"{mutation.TREE}/{mutation_killers.STATS}", json.dumps(stats(**{FUNCTION: [ONE]})))
    meta = write(root, f"{mutation.TREE}/pkg/mod.py.meta", json.dumps({"exit_code_by_key": {mutant(1): 1}}))
    write(root, "tests/support.py", "CHANGED = True\n")
    assert mutation.invalidate(root) == {"changed": 1, "verdicts": 1, "traces": 1}
    assert json.loads(meta.read_text())["exit_code_by_key"] == {mutant(1): None}
    assert json.loads((root / mutation.TREE / mutation_killers.STATS).read_text()) == {
        "tests_by_mangled_function_name": {FUNCTION: []},
        "duration_by_test": {},
    }


def test_prune_drops_copies_of_removed_files(root: Path) -> None:
    kept = [
        write(root, f"{mutation.TREE}/pkg/mod.py", ""),
        write(root, f"{mutation.TREE}/pkg/mod.py.meta", ""),
        write(root, f"{mutation.TREE}/pkg/mod.py.spans", ""),
        write(root, f"{mutation.TREE}/tests/__pycache__/gone.pyc", ""),
        write(root, f"{mutation.TREE}/{mutation_killers.STATS}", ""),
    ]
    gone = [
        write(root, f"{mutation.TREE}/pkg/gone.py", ""),
        write(root, f"{mutation.TREE}/pkg/gone.py.meta", ""),
        write(root, f"{mutation.TREE}/pkg/gone.py.spans", ""),
        write(root, f"{mutation.TREE}/tests/test_gone.py", ""),
        write(root, f"{mutation.TREE}/scripts/gone.py", ""),
    ]
    assert mutation.prune(root) == len(gone)
    assert all(path.exists() for path in kept)
    assert not any(path.exists() for path in gone)


class FakeMutmut:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[tuple[list[str], dict | None]] = []
        self.verdicts: dict[str, int | None] | None = None

    def __call__(self, command: list[str], cwd: Path, env: dict | None, check: bool) -> None:
        assert cwd == self.root
        self.calls.append((command[3:], env))
        if self.verdicts is not None:
            write(self.root, f"{mutation.TREE}/pkg/mod.py.meta", json.dumps({"exit_code_by_key": self.verdicts}))


@pytest.fixture
def fake_mutmut(root: Path, monkeypatch: pytest.MonkeyPatch) -> FakeMutmut:
    fake = FakeMutmut(root)
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def verdicts_of(root: Path, found: dict[str, int | None]) -> None:
    write(root, f"{mutation.TREE}/pkg/mod.py.meta", json.dumps({"exit_code_by_key": found}))


@pytest.mark.parametrize(
    ("found", "status", "report"),
    [
        ({mutant(1): 1, mutant(2): 3}, 0, "2 of 2 mutants killed\n"),
        ({mutant(1): 1, mutant(2): -24}, 1, f"1 of 2 mutants killed\n    {mutant(2)}: hung\n"),
        (
            {mutant(1): 1, mutant(2): 0, mutant(3): None, mutant(4): 33, mutant(5): 34},
            1,
            f"1 of 5 mutants killed\n    {mutant(2)}: survived\n    {mutant(3)}: not checked\n"
            f"    {mutant(4)}: no tests\n    {mutant(5)}: exit code 34\n",
        ),
        ({}, 1, "0 of 0 mutants killed\n"),
    ],
)
def test_check_needs_every_mutant_killed(
    root: Path, capsys: pytest.CaptureFixture[str], found: dict, status: int, report: str
) -> None:
    verdicts_of(root, found)
    assert mutation.main(["check"], root) == status
    assert capsys.readouterr().out == report


def test_check_counts_only_the_shard(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    verdicts_of(root, {"wildburrow.auth.keys.x_f__mutmut_1": 1, "wildburrow.cli.x_main__mutmut_1": None})
    assert mutation.main(["check", "--shard", "auth"], root) == 0
    assert capsys.readouterr().out == "1 of 1 mutants killed\n"
    assert mutation.main(["check"], root) == 1


@pytest.mark.parametrize(("platform", "env"), [("darwin", mutation.DARWIN_ENV), ("linux", None)])
def test_run(root: Path, fake_mutmut, monkeypatch: pytest.MonkeyPatch, platform: str, env: dict | None) -> None:
    monkeypatch.setattr(mutation.sys, "platform", platform)
    monkeypatch.setattr(mutation.os, "cpu_count", lambda: 3)
    stale = write(root, f"{mutation.TREE}/stale", "")
    verdicts_of(root, {mutant(1): None, mutant(2): None, mutant(3): None, mutant(4): None, mutant(5): 1})
    fake_mutmut.verdicts = {mutant(1): 1, mutant(2): 0, mutant(3): 36, mutant(4): 37, mutant(5): 1}
    assert mutation.main(["run"], root) == 1
    assert stale.exists()
    assert [command for command, _ in fake_mutmut.calls] == [
        ["run", "--max-children", "3"],
        ["run", "--max-children", "1", mutant(2), mutant(3)],
    ]
    assert all(passed is None if env is None else env.items() <= passed.items() for _, passed in fake_mutmut.calls)
    assert (root / mutation.TREE / mutation.BASELINE).exists()
    fake_mutmut.verdicts = {mutant(1): 1}
    assert mutation.main(["run", "--full"], root) == 0
    assert not stale.exists()
    assert [command for command, _ in fake_mutmut.calls[2:]] == [["run", "--max-children", "3"]]


def test_run_a_shard(
    root: Path, fake_mutmut, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(mutation.os, "cpu_count", lambda: 2)
    mine, theirs = "wildburrow.envfile.x_quote__mutmut_1", "wildburrow.cli.x_main__mutmut_1"
    verdicts_of(root, {mine: None, theirs: None})
    fake_mutmut.verdicts = {mine: 0, theirs: None}
    assert mutation.main(["run", "--shard", "service"], root) == 1
    assert [command for command, _ in fake_mutmut.calls] == [
        ["run", "--max-children", "2", "wildburrow.service.*", "wildburrow.envfile.*"],
        ["run", "--max-children", "1", mine],
    ]
    assert capsys.readouterr().out.endswith(f"0 of 1 mutants killed\n    {mine}: survived\n")


def test_shards_command(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert mutation.main(["shards"], root) == 0
    assert json.loads(capsys.readouterr().out) == list(mutation.SHARDS)


def test_every_module_is_in_exactly_one_shard() -> None:
    modules = [
        ".".join(path.relative_to(mutation.ROOT).with_suffix("").parts).removesuffix(".__init__") + "."
        for path in (mutation.ROOT / "wildburrow").rglob("*.py")
    ]
    prefixes = [prefix for shard in mutation.SHARDS.values() for prefix in shard]
    assert {module: sum(module.startswith(prefix) for prefix in prefixes) for module in modules} == dict.fromkeys(
        modules, 1
    ) | {"wildburrow.": 0, "wildburrow.__main__.": 0}


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
    assert mutation_killers.killers(record) == ({mutant_name: ONE} if recorded else {})


def test_runs_as_a_module(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["mutation", "key"])
    monkeypatch.delitem(sys.modules, "scripts.mutation")
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("scripts.mutation", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == mutation.cache_key(mutation.ROOT) + "\n"


@pytest.mark.parametrize(
    ("code", "stale", "expected"), [(1, {OTHER}, False), (1, {ONE}, True), (1, None, True), (-24, {OTHER}, True)]
)
def test_only_a_kill_is_settled(code: int, stale: set[str] | None, expected: bool) -> None:
    assert mutation.verdict_is_stale(mutant(1), code, stale, {FUNCTION: [ONE]}, {}) is expected


def test_a_mutants_likeliest_killers_run_first() -> None:
    function = "pkg.mod.xǁf" + mutation_killers.MARKER
    killed_by = {
        function + "1": "t::sibling",
        function + "2": "t::sibling",
        function + "3": "t::other",
        function + "4": "t::own",
        "pkg.mod.xǁf_longer" + mutation_killers.MARKER + "1": "t::unrelated",
    }
    took = {"t::cheap": 0.1, "t::dear": 9.0, "t::sibling": 5.0, "t::other": 1.0, "t::own": 3.0, "t::unrelated": 0.0}
    tests = ["t::dear", "t::unrelated", "t::other", "t::cheap", "t::own", "t::sibling", "t::new"]
    assert mutation_killers.ordered(tests, function + "4", killed_by, took) == [
        "t::own", "t::sibling", "t::other", "t::unrelated", "t::cheap", "t::dear", "t::new",
    ]  # fmt: skip
    assert mutation_killers.ordered(tests, function + "9", {}, {}) == tests


@pytest.mark.parametrize(("mutant_name", "reordered"), [(mutant(1), True), ("stats", False), ("", False)])
def test_the_order_is_set_only_for_a_mutant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutant_name: str, reordered: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MUTANT_UNDER_TEST", mutant_name)
    write(tmp_path, str(mutation_killers.STATS), json.dumps({"duration_by_test": {ONE: 2.0, TWO: 1.0}}))
    write(tmp_path, str(mutation_killers.RECORD), json.dumps({"mutant": mutant(1), "killer": OTHER}) + "\n")
    items = [SimpleNamespace(nodeid=ONE), SimpleNamespace(nodeid=TWO), SimpleNamespace(nodeid=OTHER)]
    mutation_killers.pytest_collection_modifyitems(items)
    assert [item.nodeid for item in items] == ([OTHER, TWO, ONE] if reordered else [ONE, TWO, OTHER])


def test_durations_without_a_map(tmp_path: Path) -> None:
    assert mutation_killers.durations(tmp_path / "missing") == {}
    write(tmp_path, "stats.json", "{}")
    assert mutation_killers.durations(tmp_path / "stats.json") == {}


def test_untested_mutants_get_one_full_re_trace(root: Path, fake_mutmut, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mutation.os, "cpu_count", lambda: 2)
    write(root, f"{mutation.TREE}/{mutation_killers.STATS}", json.dumps(
        {"duration_by_test": {ONE: 1.0}, "tests_by_mangled_function_name": {FUNCTION: [ONE]}}
    ))  # fmt: skip
    verdicts_of(root, {mutant(1): None, mutant(2): None})
    write(root, f"{mutation.TREE}/{mutation.BASELINE}", json.dumps(mutation.file_hashes(root)))
    runs = iter([{mutant(1): 33, mutant(2): 1}, {mutant(1): 1, mutant(2): 1}])
    fake_mutmut.verdicts = None
    calls: list[list[str]] = []

    def run(command: list[str], cwd: Path, env: dict | None, check: bool) -> None:
        calls.append(command[3:])
        assert json.loads((root / mutation.TREE / mutation_killers.STATS).read_text())["duration_by_test"] == (
            {ONE: 1.0} if len(calls) == 1 else {}
        )
        if len(calls) == 2:
            assert json.loads((root / mutation.TREE / "pkg/mod.py.meta").read_text())["exit_code_by_key"] == {
                mutant(1): None, mutant(2): 1,
            }  # fmt: skip
        verdicts_of(root, next(runs))

    monkeypatch.setattr(subprocess, "run", run)
    assert mutation.main(["run"], root) == 0
    assert calls == [["run", "--max-children", "2"], ["run", "--max-children", "2", mutant(1)]]


def test_forget_clears_only_the_named_verdicts(root: Path) -> None:
    verdicts_of(root, {mutant(1): 1, mutant(2): 0})
    write(root, f"{mutation.TREE}/pkg/other.py.meta", json.dumps({"exit_code_by_key": {"pkg.other.x_g__mutmut_1": 1}}))
    before = (root / mutation.TREE / "pkg/other.py.meta").read_text()
    mutation.forget(root / mutation.TREE, {mutant(2)})
    assert mutation.verdicts(root / mutation.TREE) == {mutant(1): 1, mutant(2): None, "pkg.other.x_g__mutmut_1": 1}
    assert (root / mutation.TREE / "pkg/other.py.meta").read_text() == before


def test_decorated_functions_only_hand_off() -> None:
    # mutmut mutates no decorated function, so one that does anything itself is code no mutant ever measures.
    unmeasured = []
    for path in sorted((mutation.ROOT / "wildburrow").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            # Inside a mutation run the source is mutmut's own rewrite, which marks what it mutated.
            decorators = [ast.unparse(decorator) for decorator in node.decorator_list]
            decorators = [decorator for decorator in decorators if not decorator.startswith("_mutmut_mutated(")]
            if decorators in ([], ["staticmethod"], ["classmethod"]):
                continue
            body = node.body[1:] if isinstance(node.body[0], ast.Expr) else node.body
            if body and not (
                len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Call)
            ):
                unmeasured.append(f"{path.relative_to(mutation.ROOT)}:{node.lineno} {node.name}")
    assert unmeasured == []
