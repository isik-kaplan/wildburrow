import argparse
import asyncio
import dataclasses
import getpass
import logging
import math
import os
import sys
from collections.abc import Sequence
from importlib.metadata import version

from wildburrow.auth.token import digest, new_token
from wildburrow.client import ssh, websocket
from wildburrow.client.config import ClientConfig, config_path, read_config, write_config
from wildburrow.config import PREFIX

COMMANDS = {"connect", "login", "serve", "hash-password", "token"}
SERVER_EXTRA = "the server needs extra dependencies: install 'wildburrow[server]'"
TOKEN_ENV = f"{PREFIX}TOKEN"
TRANSPORTS = ["ssh", "websocket"]
AUTH_METHODS = ["key", "password", "token"]
CLIENT_OPTIONS = (
    "ssh_port", "user", "transport", "auth", "identity", "url", "reconnect", "retry_delay", "retry_max",
)  # fmt: skip


def _seconds(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number of seconds, got {raw!r}") from None
    if not 0 < value < math.inf:
        raise argparse.ArgumentTypeError(f"expected a positive number of seconds, got {raw!r}")
    return value


def _client_options(parser: argparse.ArgumentParser, defaults: bool) -> None:
    default = ClientConfig("")
    parser.add_argument("--ssh-port", type=int, default=default.ssh_port if defaults else None)
    parser.add_argument("--user", default=default.user if defaults else None)
    parser.add_argument("--transport", choices=TRANSPORTS, default=default.transport if defaults else None)
    parser.add_argument("--auth", choices=AUTH_METHODS, default=default.auth if defaults else None)
    parser.add_argument("--identity", default=default.identity if defaults else None, help="SSH key for websocket")
    parser.add_argument("--url", default=default.url if defaults else None, help="websocket base URL override")
    parser.add_argument(
        "--reconnect",
        action=argparse.BooleanOptionalAction,
        default=default.reconnect if defaults else None,
        help=f"reconnect when the connection drops (default: {'on' if default.reconnect else 'off'})",
    )
    parser.add_argument(
        "--retry-delay",
        type=_seconds,
        metavar="SECONDS",
        default=default.retry_delay if defaults else None,
        help=f"first wait before reconnecting, doubled after each failure (default: {default.retry_delay:g})",
    )
    parser.add_argument(
        "--retry-max",
        type=_seconds,
        metavar="SECONDS",
        default=default.retry_max if defaults else None,
        help=f"longest wait between reconnects (default: {default.retry_max:g})",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wildburrow", description="Expose local ports on your own domain.")
    parser.add_argument("--version", action="version", version=version("wildburrow"))
    commands = parser.add_subparsers(dest="command", required=True)

    connect = commands.add_parser("connect", help="tunnel a local port (default command)")
    connect.add_argument("port", type=int)
    connect.add_argument("names", nargs="+", metavar="name", help="e.g. myapp, '*.foo', '*.bar.foo'")
    connect.add_argument("--server")
    connect.add_argument("--local-host", default="localhost")
    _client_options(connect, defaults=False)

    login = commands.add_parser("login", help="save the server and how to connect to it")
    login.add_argument("server")
    login.add_argument("--token", default="")
    _client_options(login, defaults=True)

    commands.add_parser("serve", help="run the server (configured through WILDBURROW_* variables)")
    commands.add_parser("hash-password", help="print an argon2 hash for the password auth plugin")
    token = commands.add_parser("token", help="create a token for the token auth plugin")
    token.add_argument("name")
    return parser


def _connect(args: argparse.Namespace) -> int:
    saved = read_config(config_path())
    server = args.server or (saved and saved.server)
    if not server:
        print("no server configured: run `wildburrow login <server>` or pass --server", file=sys.stderr)
        return 2
    overrides = {field: getattr(args, field) for field in CLIENT_OPTIONS if getattr(args, field) is not None}
    if token := os.environ.get(TOKEN_ENV):
        overrides["token"] = token
    config = dataclasses.replace(saved or ClientConfig(server), server=server, **overrides)
    if config.transport == "websocket":
        return websocket.run(config, args.port, args.names, args.local_host)
    return ssh.run(config, args.port, args.names, args.local_host)


def _login(args: argparse.Namespace) -> int:
    path = config_path()
    config = ClientConfig(args.server, token=args.token, **{field: getattr(args, field) for field in CLIENT_OPTIONS})
    write_config(path, config)
    print(f"saved {path}")
    return 0


def _token(args: argparse.Namespace) -> int:
    value = new_token()
    print(f"token (give this to the client): {value}")
    print(f"server line (add to {PREFIX}AUTH_TOKEN_HASHES): {args.name}:{digest(value)}")
    return 0


def _serve() -> int:
    try:
        from wildburrow.server import serve
    except ImportError:
        print(SERVER_EXTRA, file=sys.stderr)
        return 2
    from wildburrow.config import ConfigError

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        asyncio.run(serve(os.environ))
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    return 0


def _hash_password() -> int:
    try:
        from argon2 import PasswordHasher
    except ImportError:
        print(SERVER_EXTRA, file=sys.stderr)
        return 2
    password = getpass.getpass("password: ")
    if password != getpass.getpass("again: "):
        print("passwords do not match", file=sys.stderr)
        return 1
    print(PasswordHasher().hash(password))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] not in COMMANDS and not args[0].startswith("-"):
        args.insert(0, "connect")
    parsed = _parser().parse_args(args)
    match parsed.command:
        case "connect":
            return _connect(parsed)
        case "login":
            return _login(parsed)
        case "serve":
            return _serve()
        case "token":
            return _token(parsed)
        case _:
            return _hash_password()


if __name__ == "__main__":
    sys.exit(main())
