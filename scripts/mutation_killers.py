import json
import os
from pathlib import Path

import pytest

RECORD = Path("mutmut-killers.jsonl")
MARKER = "__mutmut_"


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    mutant = os.environ.get("MUTANT_UNDER_TEST", "")
    if report.failed and MARKER in mutant:
        with RECORD.open("a") as record:
            record.write(json.dumps({"mutant": mutant, "killer": report.nodeid}) + "\n")
