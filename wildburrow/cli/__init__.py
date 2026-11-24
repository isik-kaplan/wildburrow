import signal
import sys
from collections import Counter
from collections.abc import Sequence
from importlib.metadata import version
from typing import Any

import click

from wildburrow.cli import ask, client, menu, saved, server, service, tokens, users
from wildburrow.service import ServiceError

PROG = "wildburrow"
CONTEXT = {"help_option_names": ["-h", "--help"], "max_content_width": 100}
NO_INPUT = "--no-input"


class _Tunnels(click.Group):
    """`wildburrow 3000 myapp` is `wildburrow connect 3000 myapp`."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        start = int(bool(args) and args[0] == NO_INPUT)
        if len(args) > start and args[start] not in self.commands and not args[start].startswith("-"):
            args = [*args[:start], "connect", *args[start:]]
        return super().parse_args(ctx, args)

    def list_commands(self, ctx: click.Context) -> list[str]:
        return list(self.commands)


@click.group(cls=_Tunnels, context_settings=CONTEXT, invoke_without_command=True)
@click.version_option(version(PROG), "--version", prog_name=PROG, message="%(version)s")
@click.option(NO_INPUT, is_flag=True, help=f"never ask anything, failing instead; also {ask.NO_INPUT}=1")
@click.pass_context
def cli(ctx: click.Context, no_input: bool) -> int | None:
    """Expose local ports on your own domain. Alone in a terminal, asks what to do."""
    return _start(ctx, no_input)


def _start(ctx: click.Context, no_input: bool) -> int | None:
    if no_input:
        ask.turn_off()
    # `tokens` registers them itself.
    if ctx.invoked_subcommand != "tokens" and saved.setting("sync_notice"):
        _sync_notice()
    if ctx.invoked_subcommand is None:
        return _alone(ctx)


def _sync_notice() -> None:
    servers = Counter(entry["server"] for entry in tokens.unsynced())
    for where, count in servers.items():
        minted = "1 token minted with --offline isn't" if count == 1 else f"{count} tokens minted with --offline aren't"
        click.echo(
            f"{minted} registered with {where}; run: wildburrow tokens sync "
            "(or: wildburrow config set sync-notice off)",
            err=True,
        )


def _alone(ctx: click.Context) -> int:
    if not ask.interactive():
        click.echo(ctx.get_help(), err=True)
        return 2
    return menu.run()


for command in (client.connect, client.login, client.logout, client.names, client.tunnels, client.kick, client.links,
                tokens.tokens_group, users.users_group, users.join, saved.config, server.serve, service.service,
                server.passwords):  # fmt: skip
    cli.add_command(command)


# What a shell gives a command ctrl+c stopped.
INTERRUPTED = 128 + signal.SIGINT


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
    except KeyboardInterrupt:
        click.echo("interrupted", err=True)
        return INTERRUPTED
    except click.Abort, EOFError:
        click.echo("aborted", err=True)
        return 1
    return result or 0
