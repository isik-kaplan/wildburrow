import argparse
import asyncio
import dataclasses
import getpass
import logging
import os
import sys
from collections.abc import Sequence
from importlib.metadata import version

from wildburrow.auth.token import digest, new_token
from wildburrow.client import websocket
from wildburrow.client.config import ClientConfig, config_path, read_config, write_config
from wildburrow.client.ssh import ssh_command
from wildburrow.config import PREFIX

COMMANDS = {"connect", "login", "serve", "hash-password", "token"}
SERVER_EXTRA = "the server needs extra dependencies: install 'wildburrow[server]'"
TOKEN_ENV = f"{PREFIX}TOKEN"
TRANSPORTS = ["ssh", "websocket"]
AUTH_METHODS = ["key", "password", "token"]


def _client_options(parser: argparse.ArgumentParser, defaults: bool) -> None:
    default = ClientConfig("")
    parser.add_argument("--ssh-port", type=int, default=default.ssh_port if defaults else None)
    parser.add_argument("--user", default=default.user if defaults else None)
    parser.add_argument("--transport", choices=TRANSPORTS, default=default.transport if defaults else None)
    parser.add_argument("--auth", choices=AUTH_METHODS, default=default.auth if defaults else None)
    parser.add_argument("--identity", default=default.identity if defaults else None, help="SSH key for websocket")
    parser.add_argument("--url", default=default.url if defaults else None, help="websocket base URL override")


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
    overrides = {
        field: getattr(args, field)
        for field in ("ssh_port", "user", "transport", "auth", "identity", "url")
        if getattr(args, field) is not None
    }
    if token := os.environ.get(TOKEN_ENV):
        overrides["token"] = token
    config = dataclasses.replace(saved or ClientConfig(server), server=server, **overrides)
    if config.transport == "websocket":
        return websocket.run(config, args.port, args.names, args.local_host)
    command = ssh_command(config, args.port, args.names, args.local_host)
    os.execvp(command[0], command)  # noqa: S606


def _login(args: argparse.Namespace) -> int:
    path = config_path()
    config = ClientConfig(
        args.server, args.ssh_port, args.user, args.transport, args.auth, args.identity, args.token, args.url
    )
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
