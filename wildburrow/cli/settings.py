"""What `connect` takes, each by option, environment variable or question, from one declaration."""

import dataclasses
import math
from collections.abc import Callable
from typing import Any

import click
from isik.cli import ErrorStyle, HelpFormat
from isik.cli import options as isik_options
from isik.common.settings import LINES, UNSET, Group, NoEnv, NoOption, NoQuestion, Prompt, Setting, Settings

from wildburrow import durations
from wildburrow.client.config import ClientConfig
from wildburrow.config import PREFIX
from wildburrow.locks import DEFAULTS as LOCK_DEFAULTS
from wildburrow.locks import FIELDS, merged, problems

DEFAULTS = ClientConfig("")
ON_OFF = {True: "on", False: "off"}
TRANSPORTS = {
    "ssh": "ssh: your ssh binary, on port 2222",
    "websocket": "websocket: wss:// on port 443, which gets through most proxies and firewalls",
}
AUTH_METHODS = {
    "key": "key: your SSH key",
    "password": "password: asked each time you connect",
    "token": "token: one made with `wildburrow tokens new NAME` on the server",
}
# Every client setting's variable starts with this, apart from the server's own.
CLIENT_PREFIX = f"{PREFIX}CLIENT_"
# How often a link works with no limit, as typed.
ANY_USES = "any"
# A made-up user, or one link, in what locking.request reads.
BARE = ""
SERVERS = "the server's"
HELP = HelpFormat(
    default_text=lambda setting, shown: shown and f"(default: {shown})",
    default_separator=" ",
    option_file_help=lambda setting, option: f"read {option} from FILE",
)


def options(settings_class: type[Settings], **keywords: Any) -> Callable[[click.Command], click.Command]:
    """isik's `options`, laid out and erring the way every wildburrow command does."""
    # Only ever called as a decorator, while the commands are imported: before any mutant is chosen.
    return isik_options(settings_class, help=HELP, errors=ErrorStyle.MESSAGE, **keywords)  # pragma: no mutate


SAVED = (
    "saved by `wildburrow login`, which asks for it in a terminal and runs first when no login is saved; asking "
    "again on every tunnel would only repeat it"
)
GATED = NoEnv(reason="it only decides which questions follow, so there is nothing for a variable to set")


class Seconds(click.ParamType):
    name = "seconds"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> float:
        try:
            seconds = float(value)
        except ValueError:
            self.fail(f"expected a number of seconds, got {value!r}")
        if not 0 < seconds < math.inf:
            self.fail(f"expected a positive number of seconds, got {value!r}")
        return seconds


def never(given: object, no_input: bool) -> bool:
    """For commands whose questions, if they have any, are a flow of their own."""
    # Nothing a command bound with it declares is asked, so True would be the same program.
    return False  # pragma: no mutate


def duration(text: str) -> str:
    if durations.seconds(text) is None:
        raise ValueError(f"expected a duration {durations.EXAMPLES}")
    return text.strip()


def use_limit(text: str) -> int | None:
    """How often a link works: a count from 1, or `any` for None, as often as anyone likes."""
    text = text.strip().lower()
    if text == ANY_USES:
        return None
    if not text.isdigit() or int(text) < 1:
        raise ValueError(f"expected a number from 1, or {ANY_USES}")
    return int(text)


def flag(name: str) -> str:
    return "--lock-" + name.replace("_", "-")


class Connection(Settings):
    """How to reach the server, over what the saved login says."""

    token = Setting(
        str, "token to log in with; means --auth token", default=UNSET, secret=True,
        question=NoQuestion(reason="login's own questions ask for a token once token is the method chosen"),
    )  # fmt: skip
    ssh_port = Setting(
        int, "SSH port", default=UNSET, shown=str(DEFAULTS.ssh_port), min=1, max=65535,
        question=NoQuestion(reason=SAVED),
    )  # fmt: skip
    user = Setting(str, "SSH user", default=UNSET, shown="your local user", question=NoQuestion(reason=SAVED))
    transport = Setting(
        str, "how to reach the server", default=UNSET, shown=DEFAULTS.transport, choices=list(TRANSPORTS),
        question=NoQuestion(reason=SAVED),
    )  # fmt: skip
    auth = Setting(
        str, "how to log in", default=UNSET, shown=DEFAULTS.auth, choices=list(AUTH_METHODS),
        question=NoQuestion(reason=SAVED),
    )  # fmt: skip
    identity = Setting(str, "SSH key for websocket", default=UNSET, shown="", question=NoQuestion(reason=SAVED))
    url = Setting(str, "websocket base URL override", default=UNSET, shown="", question=NoQuestion(reason=SAVED))
    reconnect = Setting(
        bool, "reconnect when the connection drops", default=UNSET, shown=ON_OFF[DEFAULTS.reconnect],
        question=NoQuestion(reason=SAVED),
    )  # fmt: skip
    retry_delay = Setting(
        Seconds(), "first wait before reconnecting, doubled after each failure", default=UNSET,
        shown=f"{DEFAULTS.retry_delay:g}", metavar="SECONDS", question=NoQuestion(reason=SAVED),
    )  # fmt: skip
    retry_max = Setting(
        Seconds(), "longest wait between reconnects", default=UNSET, shown=f"{DEFAULTS.retry_max:g}",
        metavar="SECONDS", question=NoQuestion(reason=SAVED),
    )  # fmt: skip

    def given(self) -> dict[str, Any]:
        """The values given, for the saved login to be overridden with."""
        return {field.name: getattr(self, field.name) for field in dataclasses.fields(self) if _given(self, field.name)}


def _given(settings: Settings, name: str) -> bool:
    return getattr(settings, name) is not UNSET


def _locked(values: Any) -> bool:
    return values.locked


def _changing_lock(values: Any) -> bool:
    return values.more and _locking(values)


def _linking(values: Any) -> bool:
    return bool(values.link or values.links)


def _locking(values: Any) -> bool:
    return bool(values.locked or values.lock or values.lock_guest or values.link or values.links)


class Remote(Settings, prefix=CLIENT_PREFIX):
    server = Setting(str, "server to use instead of the saved one", default="", question=NoQuestion(reason=SAVED))
    connection = Group(Connection)


class Tunnel(
    Remote,
    prompt=Prompt.QUESTIONARY,
    ask_order=("locked", "lock", "lock_guest", "link", "links", "link_expires", "link_uses", "more", "local_host"),
):
    local_host = Setting(
        str, "where the local port listens", default="localhost", question="Where the local port listens",
        ask_when=lambda values: values.more,
    )  # fmt: skip
    index = Setting(
        bool, "let search engines index it", default=UNSET, shown=SERVERS,
        question=NoQuestion(
            reason="a yes or no question can't leave it to the server, which decides unless --index or --no-index says"
        ),
    )  # fmt: skip
    locked = Setting(
        bool, "Lock it, so only people you let in see it?", default=False,
        option=NoOption(reason="--lock and --link lock a tunnel; this only asks whether to before asking who"),
        env=GATED,
    )  # fmt: skip
    lock = Setting(
        str, "let USER in with PASSWORD, asked for or made up when left out; repeatable", default=(), multiple=True,
        separator=LINES, metavar="USER[:PASSWORD]",
        question="Username to give a password, as USER or USER:PASSWORD (empty when done)", ask_when=_locked,
    )  # fmt: skip
    lock_guest = Setting(
        bool, "let in a made-up user with a made-up password", default=False, negatable=False,
        question=NoQuestion(reason="naming no one when asked who may get in makes up a user, as this does"),
    )  # fmt: skip
    link = Setting(
        bool, "make a one-time link", default=False, negatable=False,
        question=NoQuestion(reason="asked as how many links, which one link is the answer 1 to"),
    )  # fmt: skip
    links = Setting(
        str, "one-time links: N of them, or one per comma-separated label; repeatable", default=(), multiple=True,
        metavar="N|LABELS", question="One-time links: how many, or labels separated by commas (empty when done)",
        ask_when=_locked,
    )  # fmt: skip
    link_expires = Setting(
        duration, "links stop working after this long", default=UNSET, shown="with the tunnel", metavar="DURATION",
        question=f"How long the links work, {durations.EXAMPLES} (empty for as long as the tunnel)",
        ask_when=_linking,
    )  # fmt: skip
    link_uses = Setting(
        use_limit, "how often each link works: a number, or any for no limit", default=1, metavar="N|any",
        question=f"How often each link works: a number, or {ANY_USES}", ask_when=_linking,
    )  # fmt: skip
    more = Setting(
        bool, "Change anything else, such as where the local port listens or how the lock works?", default=False,
        option=NoOption(reason="every setting it leads to has an option of its own, which is how to give one"),
        env=GATED,
    )  # fmt: skip
    lock_path = Setting(
        str, "login path on the tunnel's hosts", default=UNSET, shown=SERVERS, metavar="PATH",
        ask_when=_changing_lock,
    )  # fmt: skip
    lock_cookie = Setting(
        str, "login cookie's name", default=UNSET, shown=SERVERS, metavar="NAME", ask_when=_changing_lock
    )
    lock_header = Setting(
        str, "header scripts log in with, as USER:PASSWORD", default=UNSET, shown=SERVERS, metavar="HEADER",
        ask_when=_changing_lock,
    )  # fmt: skip
    lock_user_header = Setting(
        str, "header telling your app who logged in", default=UNSET, shown=SERVERS, metavar="HEADER",
        ask_when=_changing_lock,
    )  # fmt: skip
    lock_expires = Setting(
        str, "how long a login lasts, like 12h", default=UNSET, shown=SERVERS, metavar="DURATION",
        ask_when=_changing_lock,
    )  # fmt: skip
    lock_confirm_links = Setting(
        bool, "have a link wait for a click, so chat previews don't use it up", default=UNSET, shown=SERVERS,
        ask_when=_changing_lock,
    )  # fmt: skip
    lock_page = Setting(
        str, "your own login page", default=UNSET, shown=SERVERS, metavar="HTML", option_file=True,
        question=NoQuestion(reason="a page is a file of HTML, given with --lock-page-file rather than typed in"),
    )  # fmt: skip
    lock_link_page = Setting(
        str, "your own page for opening a link", default=UNSET, shown=SERVERS, metavar="HTML", option_file=True,
        question=NoQuestion(reason="a page is a file of HTML, given with --lock-link-page-file rather than typed in"),
    )  # fmt: skip
    lock_message_page = Setting(
        str, "your own page for the lock's messages", default=UNSET, shown=SERVERS, metavar="HTML",
        option_file=True,
        question=NoQuestion(reason="a page is a file of HTML, given with --lock-message-page-file, not typed in"),
    )  # fmt: skip

    def lock_settings(self) -> dict[str, Any]:
        """The lock settings given, by their names in `LockSettings`."""
        return {name: getattr(self, f"lock_{name}") for name in FIELDS if _given(self, f"lock_{name}")}

    def check(self) -> None:
        found = self.lock_settings()
        if (found or _given(self, "link_expires")) and not _locking(self):
            raise self.error("lock settings need --lock, --lock-guest, --link or --links")
        if errors := problems(merged(LOCK_DEFAULTS, found), flag):
            raise self.error("; ".join(errors))


class Login(Settings, prefix=CLIENT_PREFIX):
    connection = Group(Connection)
