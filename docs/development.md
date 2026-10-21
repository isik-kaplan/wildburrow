# Development

```sh
uv sync --all-extras
uv run pytest -n auto                                # needs Docker for the Pebble ACME tests
uv run pytest -n auto -m "not acme and not system"   # without Docker
uv run pytest -m system --no-cov tests/system        # installs the real service; CI runs it on Linux and macOS
uv run ruff check . && uv run ruff format --check .
```

Coverage stays at 100%, and every mutant has to be killed.

## Mutation runs

```sh
uv run python -m scripts.mutation run                    # re-test what changed
uv run python -m scripts.mutation run --full             # re-test everything
uv run python -m scripts.mutation run --shard commands   # one shard: commands, service, client, ...
```

- A run re-tests only what changed since the last one in `mutants/`, source and tests alike; CI keeps that directory
  cached between runs.
- CI runs each shard as a job of its own with its own cache, so a cold run takes minutes and a red shard says where to
  look.
- There is one pass: each mutant runs against the tests traced to it, the test that killed it last time and those that
  killed its siblings first. A survivor is a test to write.
- A test that hangs fails at 30 seconds; a mutant mutmut has to stop itself counts as missed, not killed.
- mutmut leaves decorated functions alone, so a decorated function only hands off to a plain one.

## Releases

Every push to `master` runs the tests and the mutation runs, then publishes to PyPI and `ghcr.io` when the version in
`pyproject.toml` isn't on PyPI yet. A release adds its section to [CHANGELOG.md](../CHANGELOG.md).
