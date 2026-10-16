"""Mutation testing that only re-tests what a change can reach.

mutmut re-tests a mutant when its function changes, but not when a test changes: an edited test keeps the kills
it earned, and a new test never runs against an old survivor. `invalidate` clears exactly those verdicts, so a
restored `mutants/` directory answers for the code and the tests as they are now.

    python -m scripts.mutation run           # re-test what changed since the cached run
    python -m scripts.mutation run --full    # re-test everything
    python -m scripts.mutation key           # the cache key for `mutants/`
"""

import argparse
import ast
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from scripts.mutation_killers import MARKER, RECORD

ROOT = Path(__file__).resolve().parent.parent
TREE = "mutants"
STATS = "mutmut-stats.json"
CICD_STATS = "mutmut-cicd-stats.json"
BASELINE = ".test-hashes.json"
WATCHED = ("src", "tests")
COPIED = ("src", "tests", "scripts")
META = ".meta"
SIDECARS = (META, ".spans")
TOOLING = ("uv.lock", "scripts/mutation.py", "scripts/mutation_killers.py")
KILLS = frozenset({1, 3})
# mutmut's timeout codes. A hang that also hangs alone is the tests never finishing, so it is settled like a kill.
HUNG = frozenset({24, -24, 36, 152, 255})
DECIDED = KILLS | HUNG
TYPE_CHECKED = 37
# macOS crashes a forked child that looks up the system proxy, which every mutant runs in.
DARWIN_ENV = {"no_proxy": "*"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def cache_key(root: Path) -> str:
    tool = tomllib.loads((root / "pyproject.toml").read_text())["tool"]
    material = {
        "mutmut": tool["mutmut"],
        "pytest": tool["pytest"],
        "python": platform.python_version(),
        "files": {name: digest((root / name).read_bytes()) for name in TOOLING},
    }
    return digest(json.dumps(material, sort_keys=True).encode())


def is_test_module(name: str) -> bool:
    return name.startswith("tests/") and name.rpartition("/")[2].startswith("test_") and name.endswith(".py")


def is_test_unit(node: ast.stmt) -> bool:
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return node.name.startswith("test")
    return isinstance(node, ast.ClassDef) and node.name.startswith("Test")


def test_unit_hashes(name: str, source: bytes) -> dict[str, str]:
    # The rest of a module holds the fixtures and helpers any of its tests can be reading.
    hashes, rest = {}, []
    for node in ast.parse(source).body:
        if is_test_unit(node):
            hashes[f"{name}::{node.name}"] = digest(ast.dump(node).encode())
        else:
            rest.append(node)
    hashes[name] = digest(ast.dump(ast.Module(body=rest, type_ignores=[])).encode())
    return hashes


def file_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for top in WATCHED:
        for path in sorted((root / top).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                name = path.relative_to(root).as_posix()
                data = path.read_bytes()
                hashes.update(test_unit_hashes(name, data) if is_test_module(name) else {name: digest(data)})
    return hashes


def changed_between(stored: dict[str, str], current: dict[str, str]) -> set[str]:
    return {name for name in current.keys() | stored.keys() if current.get(name) != stored.get(name)}


def changed_files(root: Path, current: dict[str, str]) -> set[str]:
    baseline = root / TREE / BASELINE
    if baseline.exists():
        return changed_between(json.loads(baseline.read_text()), current)
    # A cache that no baseline vouches for can't be trusted for anything.
    return set(current) if (root / TREE / STATS).exists() else set()


def unit_of(test: str) -> str:
    return test.partition("::")[2].partition("::")[0].partition("[")[0]


def module_prefix(name: str) -> str:
    return name.removeprefix("src/").removesuffix(".py").replace("/", ".") + "."


def stale_tests(changed: set[str], stats: dict, sources: bool) -> set[str] | None:
    traced: dict[str, list[str]] = stats.get("tests_by_mangled_function_name", {})
    known = set(stats.get("duration_by_test", {})) | {test for tests in traced.values() for test in tests}
    stale: set[str] = set()
    for key in changed:
        name, _, unit = key.partition("::")
        if name.startswith("src/"):
            # mutmut clears the verdicts of a changed function itself, but only tracing finds a function it gained.
            if sources:
                prefix = module_prefix(name)
                reached = {test for function, tests in traced.items() if function.startswith(prefix) for test in tests}
                if not reached:
                    return None
                stale |= reached
        elif is_test_module(name):
            stale |= {test for test in known if test.partition("::")[0] == name and (not unit or unit_of(test) == unit)}
        elif name.rpartition("/")[2] == "conftest.py":
            stale |= {test for test in known if test.startswith(name.removesuffix("conftest.py"))}
        else:
            return None
    return stale


def killers(record: Path) -> dict[str, str]:
    if not record.exists():
        return {}
    entries = (json.loads(line) for line in record.read_text().splitlines() if line)
    return {entry["mutant"]: entry["killer"] for entry in entries}


def verdict_is_stale(key: str, code: int, stale: set[str] | None, traced: dict, killed_by: dict[str, str]) -> bool:
    if stale is None or code not in DECIDED:
        return True
    if key in killed_by:
        return killed_by[key] in stale
    return not stale.isdisjoint(traced.get(key.partition(MARKER)[0], ()))


def clear_verdicts(tree: Path, stats: dict, stale: set[str] | None) -> int:
    traced = stats.get("tests_by_mangled_function_name", {})
    killed_by = killers(tree / RECORD)
    cleared = 0
    for meta_path in sorted(tree.rglob(f"*.py{META}")):
        meta = json.loads(meta_path.read_text())
        verdicts = meta["exit_code_by_key"]
        keys = [
            key
            for key, code in verdicts.items()
            if code not in (None, TYPE_CHECKED) and verdict_is_stale(key, code, stale, traced, killed_by)
        ]
        if keys:
            verdicts.update(dict.fromkeys(keys))
            meta_path.write_text(json.dumps(meta, indent=4))
            cleared += len(keys)
    return cleared


def drop_traces(stats_path: Path, stats: dict, stale: set[str] | None) -> int:
    # A test missing from the durations is a new test to mutmut, which traces it again.
    durations: dict[str, float] = stats.get("duration_by_test", {})
    dropped = set(durations) if stale is None else stale & set(durations)
    if not dropped:
        return 0
    stats["duration_by_test"] = {test: time for test, time in durations.items() if test not in dropped}
    stats["tests_by_mangled_function_name"] = {
        function: [test for test in tests if test not in dropped]
        for function, tests in stats["tests_by_mangled_function_name"].items()
    }
    stats_path.write_text(json.dumps(stats, indent=4))
    return len(dropped)


def invalidate(root: Path) -> dict[str, int]:
    tree = root / TREE
    current = file_hashes(root)
    changed = changed_files(root, current)
    stats_path = tree / STATS
    stats = json.loads(stats_path.read_text()) if stats_path.exists() else {}
    result = {"changed": len(changed), "verdicts": 0, "traces": 0}
    if changed:
        result["verdicts"] = clear_verdicts(tree, stats, stale_tests(changed, stats, sources=False))
        result["traces"] = drop_traces(stats_path, stats, stale_tests(changed, stats, sources=True))
    tree.mkdir(exist_ok=True)
    (tree / BASELINE).write_text(json.dumps(current, indent=4, sort_keys=True))
    return result


def prune(root: Path) -> int:
    # mutmut refreshes its copies but never deletes one, so a removed test would keep running.
    tree = root / TREE
    removed = 0
    for top in COPIED:
        for copy in sorted((tree / top).rglob("*")):
            if copy.is_file() and "__pycache__" not in copy.parts:
                relative = copy.relative_to(tree)
                source = next(
                    (relative.name.removesuffix(s) for s in SIDECARS if relative.name.endswith(s)), relative.name
                )
                if not (root / relative.with_name(source)).exists():
                    copy.unlink()
                    removed += 1
    return removed


def verdicts(tree: Path) -> dict[str, int | None]:
    found: dict[str, int | None] = {}
    for meta_path in sorted(tree.rglob(f"*.py{META}")):
        found.update(json.loads(meta_path.read_text())["exit_code_by_key"])
    return found


def mutmut(root: Path, *args: str, check: bool = True) -> None:
    env = os.environ | DARWIN_ENV if sys.platform == "darwin" else None
    subprocess.run([sys.executable, "-m", "mutmut", *args], cwd=root, env=env, check=check)  # noqa: S603


def check(root: Path) -> int:
    counts = json.loads((root / TREE / CICD_STATS).read_text())
    print(f"{counts['killed']} of {counts['total']} mutants killed, {counts['timeout']} hung")
    # A hang that survived running alone is the tests never finishing, which is the mutant caught.
    if counts["total"] and counts["killed"] + counts["timeout"] == counts["total"]:
        return 0
    mutmut(root, "results", check=False)
    return 1


def run(root: Path, full: bool) -> int:
    if full:
        shutil.rmtree(root / TREE, ignore_errors=True)
    print(f"{prune(root)} copies of removed files dropped", flush=True)
    print(
        "{changed} files changed, {verdicts} verdicts cleared, {traces} traces dropped".format(**invalidate(root)),
        flush=True,
    )
    settled = {key for key, code in verdicts(root / TREE).items() if code is not None}
    mutmut(root, "run", "--max-children", str(os.cpu_count()), check=False)
    # Under a full load a slow test can read as a hang or a hang as a pass, so whatever didn't die runs again alone.
    tested = {key: code for key, code in verdicts(root / TREE).items() if key not in settled}
    if alive := [key for key, code in tested.items() if code not in KILLS and code != TYPE_CHECKED]:
        mutmut(root, "run", "--max-children", "1", *alive, check=False)
    mutmut(root, "export-cicd-stats")
    return check(root)


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(prog="python -m scripts.mutation", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("key", help="print the cache key for mutants/")
    commands.add_parser("check", help="fail unless every mutant was killed")
    run_parser = commands.add_parser("run", help="re-test what changed, then check")
    run_parser.add_argument("--full", action="store_true", help="discard mutants/ and re-test everything")
    args = parser.parse_args(argv)
    if args.command == "key":
        print(cache_key(root))
        return 0
    if args.command == "check":
        return check(root)
    return run(root, args.full)


if __name__ == "__main__":
    sys.exit(main())
