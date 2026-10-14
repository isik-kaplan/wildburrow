from pathlib import Path

import pytest

from wildburrow.auth.base import Authenticator
from wildburrow.core.context import ServerContext


@pytest.fixture
def ctx(tmp_path: Path) -> ServerContext:
    return ServerContext("example.com", 5, tmp_path, Authenticator([]))
