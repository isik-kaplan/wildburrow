"""Mutation testing that only re-tests what a change can reach.

mutmut re-tests a mutant when its function changes, but not when a test changes: an edited test keeps the kills
it earned, and a new test never runs against an old survivor. `invalidate` clears exactly those verdicts, so a
restored `mutants/` directory answers for the code and the tests as they are now.

    python -m scripts.mutation run                   # re-test what changed since the cached run
    python -m scripts.mutation run --full            # re-test everything
    python -m scripts.mutation run --shard commands  # only the mutants of one shard
    python -m scripts.mutation shards                # the shard names
    python -m scripts.mutation key                   # the cache key for `mutants/`
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

from scripts.mutation_killers import MARKER, RECORD, STATS, killers

ROOT = Path(__file__).resolve().parent.parent
TREE = "mutants"
BASELINE = ".test-hashes.json"
TESTS = "tests"
META = ".meta"
SIDECARS = (META, ".spans")
TOOLING = ("uv.lock", "scripts/mutation.py", "scripts/mutation_killers.py")
KILLS = frozenset({1, 3})
# mutmut stopping the tests itself: a hang that no test turned into a failure, which a run without mutmut never ends.
HUNG = dict.fromkeys((24, -24, 36, 152, 255), "hung")
TYPE_CHECKED = 37
# macOS crashes a forked child that looks up the system proxy, which every mutant runs in.
DARWIN_ENV = {"no_proxy": "*"}
# Split by what the code is for rather than by size, so a failing shard says where to look.
SHARDS = {
    "commands": ("wildburrow.cli.",),
    "service": ("wildburrow.service.", "wildburrow.envfile."),
    "client": ("wildburrow.client.",),
    "transports": ("wildburrow.transports.",),
    "edge": (
        "wildburrow.edge.", "wildburrow.server.", "wildburrow.core.", "wildburrow.protocol.", "wildburrow.streams.",
        "wildburrow.plugins.", "wildburrow.config.", "wildburrow.locks.", "wildburrow.durations.",
    ),
    "certs": ("wildburrow.certs.", "wildburrow.dns."),
    "auth": ("wildburrow.auth.", "wildburrow.tokens."),
}  # fmt: skip
EVERY_MUTANT = ("",)
NO_TESTS = 33
STATUS = {None: "not checked", 0: "survived", NO_TESTS: "no tests"} | HUNG


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


def source_paths(root: Path) -> list[str]:
    return tomllib.loads((root / "pyproject.toml").read_text())["tool"]["mutmut"]["source_paths"]


def is_test_module(name: str) -> bool:
    return name.startswith(f"{TESTS}/") and name.rpartition("/")[2].startswith("test_") and name.endswith(".py")


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
    for top in (*source_paths(root), TESTS):
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
    return name.removesuffix(".py").replace("/", ".") + "."


def stale_tests(changed: set[str], stats: dict, sources: bool) -> set[str] | None:
    traced: dict[str, list[str]] = stats.get("tests_by_mangled_function_name", {})
    known = set(stats.get("duration_by_test", {})) | {test for tests in traced.values() for test in tests}
    stale: set[str] = set()
    for key in changed:
        name, _, unit = key.partition("::")
        if not name.startswith(f"{TESTS}/"):
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


def verdict_is_stale(key: str, code: int, stale: set[str] | None, traced: dict, killed_by: dict[str, str]) -> bool:
    if stale is None or code not in KILLS:
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


def forget(tree: Path, keys: set[str]) -> None:
    for meta_path in sorted(tree.rglob(f"*.py{META}")):
        meta = json.loads(meta_path.read_text())
        if found := keys & meta["exit_code_by_key"].keys():
            meta["exit_code_by_key"].update(dict.fromkeys(found))
            meta_path.write_text(json.dumps(meta, indent=4))


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
    for top in (*source_paths(root), TESTS, "scripts"):
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


def check(root: Path, prefixes: tuple[str, ...] = EVERY_MUTANT) -> int:
    found = {key: code for key, code in verdicts(root / TREE).items() if key.startswith(prefixes)}
    killed = sum(code in KILLS for code in found.values())
    print(f"{killed} of {len(found)} mutants killed")
    missed = {key: code for key, code in found.items() if code not in KILLS}
    for key, code in missed.items():
        print(f"    {key}: {STATUS.get(code, f'exit code {code}')}")
    return 0 if found and not missed else 1


def damaged(tree: Path) -> bool:
    """Whether a run stopped mid-write left any of the cache unreadable, which no later run could read either."""
    try:
        for path in [*tree.rglob(f"*.py{META}"), tree / STATS, tree / BASELINE]:
            if path.exists():
                json.loads(path.read_text())
        killers(tree / RECORD)
    except ValueError, KeyError, TypeError:
        return True
    return False


def run(root: Path, full: bool, shard: str | None) -> int:
    prefixes = SHARDS[shard] if shard else EVERY_MUTANT
    if not full and damaged(root / TREE):
        print(f"{TREE}/ was left half written, so this run starts over", flush=True)
        full = True
    if full:
        shutil.rmtree(root / TREE, ignore_errors=True)
    print(f"{prune(root)} copies of removed files dropped", flush=True)
    print(
        "{changed} files changed, {verdicts} verdicts cleared, {traces} traces dropped".format(**invalidate(root)),
        flush=True,
    )
    settled = {key for key, code in verdicts(root / TREE).items() if code is not None}
    selection = [prefix + "*" for prefix in prefixes if prefix]
    mutmut(root, "run", "--max-children", str(os.cpu_count()), *selection, check=False)
    # Under a full load a slow test can read as a hang or a hang as a pass, so whatever didn't die runs again alone.
    tested = {
        key: code for key, code in verdicts(root / TREE).items() if key not in settled and key.startswith(prefixes)
    }
    if untraced := [key for key, code in tested.items() if code == NO_TESTS]:
        # A function the map never traced has no tests to run, and only tracing everything again finds them.
        stats_path = root / TREE / STATS
        drop_traces(stats_path, json.loads(stats_path.read_text()), None)
        forget(root / TREE, set(untraced))
        mutmut(root, "run", "--max-children", str(os.cpu_count()), *untraced, check=False)
        tested.update((key, code) for key, code in verdicts(root / TREE).items() if key in untraced)
    if alive := [key for key, code in tested.items() if code not in KILLS and code != TYPE_CHECKED]:
        mutmut(root, "run", "--max-children", "1", *alive, check=False)
    return check(root, prefixes)


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(prog="python -m scripts.mutation", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("key", help="print the cache key for mutants/")
    commands.add_parser("shards", help="print the shard names as JSON")
    check_parser = commands.add_parser("check", help="fail unless every mutant was killed")
    run_parser = commands.add_parser("run", help="re-test what changed, then check")
    run_parser.add_argument("--full", action="store_true", help="discard mutants/ and re-test everything")
    for sub in (check_parser, run_parser):
        sub.add_argument("--shard", choices=list(SHARDS), help="only the mutants of this shard")
    args = parser.parse_args(argv)
    if args.command == "key":
        print(cache_key(root))
        return 0
    if args.command == "shards":
        print(json.dumps(list(SHARDS)))
        return 0
    if args.command == "check":
        return check(root, SHARDS[args.shard] if args.shard else EVERY_MUTANT)
    return run(root, args.full, args.shard)


if __name__ == "__main__":
    sys.exit(main())
