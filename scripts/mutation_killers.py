"""Records which test killed each mutant, and runs a mutant's likeliest killers first."""

import json
import math
import os
from collections import Counter
from pathlib import Path

import pytest

RECORD = Path("mutmut-killers.jsonl")
STATS = Path("mutmut-stats.json")
MARKER = "__mutmut_"


def killers(record: Path) -> dict[str, str]:
    if not record.exists():
        return {}
    entries = (json.loads(line) for line in record.read_text().splitlines() if line)
    return {entry["mutant"]: entry["killer"] for entry in entries}


def durations(stats: Path) -> dict[str, float]:
    return json.loads(stats.read_text()).get("duration_by_test", {}) if stats.exists() else {}


def ordered(nodeids: list[str], mutant: str, killed_by: dict[str, str], took: dict[str, float]) -> list[str]:
    """What killed this mutant before, then what killed others of its function, most often first, then the cheapest."""
    function = mutant.partition(MARKER)[0] + MARKER
    siblings = Counter(killer for name, killer in killed_by.items() if name.startswith(function))
    own = killed_by.get(mutant)
    return sorted(nodeids, key=lambda nodeid: (nodeid != own, -siblings[nodeid], took.get(nodeid, math.inf)))


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    # pytest runs in collection order whatever order the tests were named in, so this is where the order is set.
    mutant = os.environ.get("MUTANT_UNDER_TEST", "")
    if MARKER not in mutant:
        return
    order = ordered([item.nodeid for item in items], mutant, killers(RECORD), durations(STATS))
    position = {nodeid: index for index, nodeid in enumerate(order)}
    items.sort(key=lambda item: position[item.nodeid])


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    mutant = os.environ.get("MUTANT_UNDER_TEST", "")
    if report.failed and MARKER in mutant:
        with RECORD.open("a") as record:
            record.write(json.dumps({"mutant": mutant, "killer": report.nodeid}) + "\n")
