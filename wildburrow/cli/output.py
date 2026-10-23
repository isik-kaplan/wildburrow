from datetime import UTC, datetime

import click

NEVER = "never"


def table(rows: list[tuple[str, ...]]) -> None:
    """`rows` in columns as wide as their widest cell, the first row being the headings."""
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    for row in rows:
        click.echo("  ".join(row[column].ljust(widths[column]) for column in range(len(row))).rstrip())


def when(timestamp: int | None) -> str:
    if timestamp is None:
        return NEVER
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%d %H:%M UTC")
