import sys
from collections.abc import Sequence
from importlib.metadata import version
from typing import Any

import click

from wildburrow.cli import client, server, service
from wildburrow.service import ServiceError

PROG = "wildburrow"
CONTEXT = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


class _Tunnels(click.Group):
    """`wildburrow 3000 myapp` is `wildburrow connect 3000 myapp`."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["connect", *args]
        return super().parse_args(ctx, args)

    def list_commands(self, ctx: click.Context) -> list[str]:
        return list(self.commands)


@click.group(cls=_Tunnels, context_settings=CONTEXT)
@click.version_option(version(PROG), "--version", prog_name=PROG, message="%(version)s")
def cli() -> None:
    """Expose local ports on your own domain."""


for command in (client.connect, client.login, client.logout, server.serve, service.service, server.hash_password,
                server.token):  # fmt: skip
    cli.add_command(command)


def main(argv: Sequence[str] | None = None) -> int:
    # Driven by hand rather than through cli.main, so a command's return value is the exit code.
    try:
        with cli.make_context(PROG, list(sys.argv[1:] if argv is None else argv)) as ctx:
            result: Any = cli.invoke(ctx)
    except click.exceptions.Exit as exc:
        return exc.exit_code
    except click.ClickException as exc:
        exc.show()
        return exc.exit_code
    except ServiceError as exc:
        click.echo(str(exc), err=True)
        return 1
    except click.Abort, KeyboardInterrupt, EOFError:
        click.echo("aborted", err=True)
        return 1
    return result or 0
