import base64
import dataclasses
import hashlib
import hmac
import re
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.unit.test_registry import FakeTunnel
from wildburrow import protocol
from wildburrow.config import ConfigError
from wildburrow.core.context import ServerContext
from wildburrow.core.errors import BindRejected
from wildburrow.core.locks import (
    ATTEMPT_WINDOW,
    MAX_CODES,
    SEEN_EVERY,
    Code,
    Entry,
    Lock,
    Locking,
    build,
    challenge,
    digest,
    entry_id,
)
from wildburrow.core.names import Name
from wildburrow.core.types import Identity
from wildburrow.locks import (
    DEFAULTS,
    LINK,
    MAX_PAGE_BYTES,
    PASSWORD,
    LockSettings,
    ServerLockSettings,
    merged,
    next_links,
    problems,
    safe_path,
)
from wildburrow.server import locking

SECRET = bytes(range(32))
SECRET_TEXT = base64.urlsafe_b64encode(SECRET).decode()
NOW = 1_800_000_000
HOME = "foo.example.com"
ALICE = Identity("alice", "token", "alice")
BOB = Identity("bob", "token", "bob")


class Clock:
    def __init__(self) -> None:
        self.now: float = NOW

    def __call__(self) -> float:
        return self.now


class Changes(list[dict[str, Any]]):
    def __call__(self, state: dict[str, Any]) -> None:
        self.append(state)


def lock_of(
    settings: LockSettings = DEFAULTS, on_domain: bool = False, secure: bool = False, **locking_options: int
) -> tuple[Lock, Clock, Changes]:
    clock, changes = Clock(), Changes()
    home = "example.com" if on_domain else HOME
    lock = Lock(SECRET, settings, home, on_domain, secure, Locking(settings, **locking_options), changes, clock)
    return lock, clock, changes


def test_the_defaults() -> None:
    assert dataclasses.asdict(DEFAULTS) == {
        "path": "/_wildburrow/login",
        "cookie": "wildburrow",
        "header": "X-Wildburrow-Auth",
        "user_header": "X-Wildburrow-User",
        "expires": "",
        "confirm_links": True,
        "page": "",
        "link_page": "",
        "message_page": "",
    }
    assert (ServerLockSettings().attempts, ServerLockSettings().code_expires) == (10, "10m")
    assert Locking() == Locking(DEFAULTS, 10, 600)


@pytest.mark.parametrize(("expires", "seconds"), [("", None), ("1h", 3600), ("30m", 1800)])
def test_a_login_lasts_its_lifetime(expires: str, seconds: int | None) -> None:
    assert LockSettings(expires=expires).lifetime() == seconds


def named(name: str) -> str:
    return f"<{name}>"


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"path": "nope"}, "<path>: expected a path like /_wildburrow/login, got 'nope'"),
        ({"path": "/"}, "<path>: expected a path like /_wildburrow/login, got '/'"),
        ({"path": "/a b"}, "<path>: expected a path like /_wildburrow/login, got '/a b'"),
        ({"path": "/a?b"}, "<path>: expected a path like /_wildburrow/login, got '/a?b'"),
        ({"cookie": "a b"}, "<cookie>: 'a b' can't be a cookie name"),
        ({"cookie": ""}, "<cookie>: '' can't be a cookie name"),
        ({"header": "X Y"}, "<header>: 'X Y' can't be a header of its own"),
        ({"header": "Cookie"}, "<header>: 'Cookie' can't be a header of its own"),
        ({"user_header": "host"}, "<user_header>: 'host' can't be a header of its own"),
        ({"user_header": "x-wildburrow-auth"}, "<header> and <user_header> must differ"),
        ({"expires": "soon"}, "<expires>: expected a duration like 30m, 12h or 7d, or empty, got 'soon'"),
        ({"page": "x" * (MAX_PAGE_BYTES + 1)}, f"<page>: larger than {MAX_PAGE_BYTES} bytes"),
        ({"link_page": "é" * (MAX_PAGE_BYTES // 2 + 1)}, f"<link_page>: larger than {MAX_PAGE_BYTES} bytes"),
        ({"message_page": "x" * (MAX_PAGE_BYTES + 1)}, f"<message_page>: larger than {MAX_PAGE_BYTES} bytes"),
    ],
)
def test_problems_name_the_setting(changes: dict[str, str], problem: str) -> None:
    assert problems(dataclasses.replace(DEFAULTS, **changes), named) == [problem]


def test_sound_settings_have_no_problems() -> None:
    sound = LockSettings("/.in/x", "pass", "X-A", "X-B", "12h", False, "x" * MAX_PAGE_BYTES, "<p>", "<q>")
    assert problems(sound, named) == []
    assert problems(DEFAULTS, named) == []


def test_every_problem_is_told() -> None:
    assert len(problems(LockSettings(path="x", cookie=" ", expires="x"), named)) == 3


@pytest.mark.parametrize("path", ["/", "/a?b=c&d", "/x/y#z", "/%2F"])
def test_safe_paths(path: str) -> None:
    assert safe_path(path)


@pytest.mark.parametrize("path", ["", "a", "//evil", "/\\evil", "/a b", "/a\r\nX: y", "/\x7f", "/é"])
def test_unsafe_paths(path: str) -> None:
    assert not safe_path(path)


@given(st.text(max_size=20))
def test_a_safe_path_never_leaves_the_host(path: str) -> None:
    if safe_path(path):
        assert path.startswith("/")
        assert path[1:2] not in ("/", "\\")
        assert all(33 <= ord(char) < 127 for char in path)


@pytest.mark.parametrize(
    ("taken", "count", "labels"),
    [
        ([], 1, ["link-1"]),
        ([], 3, ["link-1", "link-2", "link-3"]),
        (["link-1", "link-3", "bob", "link-x", "link-01", "link-", "xlink-9"], 2, ["link-4", "link-5"]),
        (["link-10"], 1, ["link-11"]),
        (["link-1"], 0, []),
    ],
)
def test_links_are_numbered_on(taken: list[str], count: int, labels: list[str]) -> None:
    assert next_links(taken, count) == labels


def test_merged_takes_the_clients_settings() -> None:
    assert merged(DEFAULTS, {"path": "/in", "confirm_links": False}) == LockSettings(path="/in", confirm_links=False)
    assert merged(DEFAULTS, {}) == DEFAULTS


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ([], "lock settings must be an object"),
        ({"attempts": 1}, "'attempts' isn't a lock setting"),
        ({"path": 1}, "lock setting 'path' has the wrong type"),
        ({"confirm_links": "yes"}, "lock setting 'confirm_links' has the wrong type"),
        ({"cookie": True}, "lock setting 'cookie' has the wrong type"),
    ],
)
def test_merged_refuses_what_isnt_a_setting(overrides: Any, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        merged(DEFAULTS, overrides)


def test_digests_and_challenges() -> None:
    assert digest("x") == hashlib.sha256(b"x").hexdigest()
    assert challenge("v") == base64.urlsafe_b64encode(hashlib.sha256(b"v").digest()).rstrip(b"=").decode()
    assert len(challenge("")) == 43


def test_a_lock_is_known_by_its_secret() -> None:
    lock, _, _ = lock_of()
    assert lock.id == hmac.new(SECRET, b"id", hashlib.sha256).hexdigest()[:16]
    other = Lock(bytes(32), DEFAULTS, HOME, False, False, Locking(), Changes())
    assert other.id != lock.id
    assert len(lock.id) == 16


def test_where_a_lock_lives() -> None:
    lock, _, _ = lock_of()
    assert (lock.home, lock.prefix, lock.scheme, lock.code_seconds) == (HOME, "/_wildburrow/login", "http", 600)
    assert lock.link_url("K") == f"http://{HOME}/_wildburrow/login/link/K"
    homed, _, _ = lock_of(on_domain=True, secure=True)
    assert homed.prefix == f"{protocol.LOCK_PATH}{homed.id}"
    assert homed.link_url("K") == f"https://example.com/_wildburrow/lock/{homed.id}/link/K"
    assert lock_of(code_seconds=5)[0].code_seconds == 5


def P(label: str) -> str:
    return entry_id(PASSWORD, label)


def L(label: str) -> str:
    return entry_id(LINK, label)


def test_cookie_names() -> None:
    plain, _, _ = lock_of()
    assert plain.cookie_name() == plain.home_cookie_name() == "wildburrow"
    assert plain.pending_name() == "wildburrow-pending"
    secure, _, _ = lock_of(LockSettings(cookie="pass"), secure=True)
    assert secure.cookie_name() == secure.home_cookie_name() == "__Host-pass"
    assert secure.pending_name() == "__Host-pass-pending"
    homed, _, _ = lock_of(on_domain=True, secure=True)
    assert homed.home_cookie_name() == f"__Host-wildburrow-{homed.id}"
    assert homed.cookie_name() == "__Host-wildburrow"
    assert homed.pending_name() == "__Host-wildburrow-pending"


def test_passwords_log_in() -> None:
    lock, _, _ = lock_of()
    lock.add_password("alice", "wonderland")
    lock.add_link("bob", digest("key"), "", "/", None)
    assert lock.login("alice", "wonderland") is lock.entries[P("alice")]
    assert lock.login("alice", "wrong") is None
    assert lock.login("carol", "wonderland") is None
    assert lock.login("bob", "") is None
    assert lock.entries[P("alice")].password != b"wonderland"
    assert lock.has_passwords()
    lock.end("alice")
    assert lock.login("alice", "wonderland") is None
    assert not lock.has_passwords()


def test_a_lock_of_links_has_no_passwords() -> None:
    lock, _, _ = lock_of()
    lock.add_link("bob", digest("key"), "", "/", None)
    assert not lock.has_passwords()


def test_failures_slow_the_lock_down_for_a_minute() -> None:
    lock, clock, _ = lock_of(attempts=2)
    lock.add_password("alice", "wonderland")
    lock.login("alice", "x")
    assert not lock.limited()
    clock.now += 1
    lock.login("nobody", "x")
    assert lock.limited()
    assert lock.login("alice", "wonderland") is not None
    clock.now = NOW + ATTEMPT_WINDOW - 0.5
    assert lock.limited()
    clock.now = NOW + ATTEMPT_WINDOW
    assert not lock.limited()
    clock.now = NOW + ATTEMPT_WINDOW + 1
    assert not lock.limited()
    lock.login("alice", "x")
    assert not lock.limited()


@pytest.mark.parametrize(("expires", "until"), [("", 0), ("1h", NOW + 3600)])
def test_until(expires: str, until: int) -> None:
    lock, _, _ = lock_of(LockSettings(expires=expires))
    assert lock.until() == until


def test_now_is_whole_seconds() -> None:
    lock, clock, _ = lock_of()
    clock.now = NOW + 0.9
    assert lock.now() == NOW


def test_cookies_let_in_their_holder_on_their_host() -> None:
    lock, clock, _ = lock_of()
    lock.add_password("a.b", "pw")
    entry = lock.entries[P("a.b")]
    cookie = lock.cookie(HOME, entry, 0)
    assert cookie.startswith("password:a.b.0.")
    assert lock.admitted(HOME, cookie) == (entry, 0)
    assert lock.admitted("other.example.com", cookie) is None
    label, until, mac = cookie.rsplit(".", 2)
    assert lock.admitted(HOME, f"{label}.{until}.{mac[:-1]}x") is None
    assert lock.admitted(HOME, f"{label}.1.{mac}") is None
    assert lock.admitted(HOME, f"password:a.b.x.{mac}") is None
    assert lock.admitted(HOME, None) is None
    assert lock.admitted(HOME, "a.b") is None
    assert lock.admitted(HOME, "") is None
    other = Lock(bytes(32), DEFAULTS, HOME, False, False, Locking(), Changes(), clock)
    other.add_password("a.b", "pw")
    assert other.admitted(HOME, cookie) is None


def test_a_cookie_is_an_hmac_of_its_host_login_and_end() -> None:
    lock, _, _ = lock_of()
    lock.add_password("alice", "pw")
    mac = hmac.new(SECRET, "\0".join(["cookie", HOME, "password:alice", "7"]).encode(), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(mac).decode().rstrip("=")
    assert lock.cookie(HOME, lock.entries[P("alice")], 7) == f"password:alice.7.{expected}"


def test_a_cookie_ends_with_its_login() -> None:
    lock, clock, _ = lock_of()
    lock.add_password("alice", "pw")
    entry = lock.entries[P("alice")]
    cookie = lock.cookie(HOME, entry, NOW + 10)
    assert lock.admitted(HOME, cookie) == (entry, NOW + 10)
    clock.now = NOW + 9.5
    assert lock.admitted(HOME, cookie) == (entry, NOW + 10)
    clock.now = NOW + 10
    assert lock.admitted(HOME, cookie) is None
    lasting = lock.cookie(HOME, entry, 0)
    assert lock.admitted(HOME, lasting) == (entry, 0)
    lock.end("alice")
    assert lock.admitted(HOME, lasting) is None


def test_a_cookie_for_a_login_that_isnt_there_lets_no_one_in() -> None:
    lock, _, _ = lock_of()
    ghost = Entry("ghost", PASSWORD)
    assert lock.admitted(HOME, lock.cookie(HOME, ghost, 0)) is None


def test_links_open_once() -> None:
    lock, clock, changes = lock_of()
    lock.add_password("alice", "pw")
    lock.add_link("old", digest("other"), "", "/", None)
    key = lock.mint("bob", "a.foo.example.com", "/x", None, 1)
    entry = lock.entries[L("bob")]
    assert (entry.kind, entry.key, entry.host, entry.path) == (LINK, digest(key), "a.foo.example.com", "/x")
    unused = {"expires": None, "used": None, "spent": 0, "uses": 1}
    old = {"key": digest("other"), "host": "", "path": "/", **unused}
    bob = {"key": digest(key), "host": "a.foo.example.com", "path": "/x", **unused}
    assert changes == [{"links": {"old": old, "bob": bob}, "ended": [], "counts": {}}]
    assert lock.link(key) is entry
    assert lock.link("wrong") is None
    clock.now += 5
    lock.spend(entry)
    assert (entry.used, entry.logins, entry.seen) == (NOW + 5, 1, NOW + 5)
    assert changes[-1] == lock.state()
    assert len(changes) == 2
    assert lock.link(key) is None


def test_links_end_and_expire() -> None:
    lock, clock, _ = lock_of()
    ended = lock.mint("a", "", "/", None, 1)
    lock.end("a")
    assert lock.link(ended) is None
    expiring = lock.mint("b", "", "/", NOW + 10, 1)
    clock.now = NOW + 9
    assert lock.link(expiring) is lock.entries[L("b")]
    clock.now = NOW + 10
    assert lock.link(expiring) is None


def test_logins_and_sightings_are_counted() -> None:
    lock, clock, _ = lock_of()
    lock.add_password("alice", "pw")
    entry = lock.entries[P("alice")]
    lock.logged_in(entry)
    clock.now += 3
    lock.seen(entry)
    assert (entry.logins, entry.seen) == (1, NOW + 3)


def test_ending_tells_the_client_once() -> None:
    lock, _, changes = lock_of()
    lock.add_password("alice", "pw")
    assert lock.end("alice")
    assert not lock.end("alice")
    assert not lock.end("nobody")
    assert changes == [{"links": {}, "ended": ["password:alice"], "counts": {}}]


def test_codes_carry_a_login_to_one_host_in_one_browser() -> None:
    lock, _, _ = lock_of()
    lock.add_password("alice", "pw")
    entry = lock.entries[P("alice")]
    code = lock.issue("a.foo.example.com", challenge("v"), entry, 7, "/to")
    assert lock.redeem(code, "b.foo.example.com", "v") is None
    code = lock.issue("a.foo.example.com", challenge("v"), entry, 7, "/to")
    assert lock.redeem(code, "a.foo.example.com", "w") is None
    code = lock.issue("a.foo.example.com", challenge("v"), entry, 7, "/to")
    redeemed = lock.redeem(code, "a.foo.example.com", "v")
    assert redeemed == (Code("a.foo.example.com", challenge("v"), "password:alice", 7, "/to", NOW), entry)
    assert lock.redeem(code, "a.foo.example.com", "v") is None
    assert lock.redeem("unknown", "a.foo.example.com", "v") is None


def test_codes_expire_and_die_with_their_login() -> None:
    lock, clock, _ = lock_of(code_seconds=10)
    lock.add_password("alice", "pw")
    entry = lock.entries[P("alice")]
    code = lock.issue("a", challenge("v"), entry, 0, "/")
    clock.now = NOW + 9
    kept = lock.issue("a", challenge("v"), entry, 0, "/")
    clock.now = NOW + 10
    assert lock.redeem(code, "a", "v") is None
    assert lock.redeem(kept, "a", "v") is not None
    ended = lock.issue("a", challenge("v"), entry, 0, "/")
    lock.end("alice")
    assert lock.redeem(ended, "a", "v") is None


def test_old_codes_make_way_for_new_ones() -> None:
    lock, _, _ = lock_of()
    lock.add_password("alice", "pw")
    entry = lock.entries[P("alice")]
    first = lock.issue("a", challenge("v"), entry, 0, "/")
    second = lock.issue("a", challenge("v"), entry, 0, "/")
    for _ in range(MAX_CODES - 2):
        lock.issue("a", challenge("v"), entry, 0, "/")
    assert len(lock._codes) == MAX_CODES
    lock.issue("a", challenge("v"), entry, 0, "/")
    assert len(lock._codes) == MAX_CODES
    assert lock.redeem(first, "a", "v") is None
    assert lock.redeem(second, "a", "v") is not None


def test_state_and_listing() -> None:
    lock, _, _ = lock_of()
    lock.add_password("alice", "pw")
    bob = lock.add_link("bob", digest("k"), "a.foo.example.com", "/x", NOW + 60)
    bob.used, bob.spent, bob.uses, bob.logins, bob.seen = NOW, 1, 3, 1, NOW + 1
    lock.end("alice")
    assert lock.state() == {
        "links": {
            "bob": {
                "key": digest("k"), "host": "a.foo.example.com", "path": "/x", "expires": NOW + 60, "used": NOW,
                "spent": 1, "uses": 3,
            }
        },
        "ended": ["password:alice"],
        "counts": {"link:bob": {"logins": 1, "seen": NOW + 1}},
    }  # fmt: skip
    assert lock.listing() == [
        {"who": "alice", "kind": "password", "used": None, "spent": 0, "uses": 1, "logins": 0, "seen": None,
         "expires": None, "ended": True},
        {"who": "bob", "kind": "link", "used": NOW, "spent": 1, "uses": 3, "logins": 1, "seen": NOW + 1,
         "expires": NOW + 60, "ended": False},
    ]  # fmt: skip


def spec(**changes: Any) -> dict[str, Any]:
    return {"secret": SECRET_TEXT, "users": {"alice": "pw"}} | changes


def built(raw: Any, on_domain: bool = False) -> tuple[Lock, list[tuple[str, str]]]:
    return build(raw, HOME, on_domain, True, Locking(), Changes(), Clock())


def test_a_lock_is_built_as_asked() -> None:
    raw = spec(
        links={"bob": {"key": digest("k"), "host": "a.foo.example.com", "path": "/x", "expires": NOW + 1, "used": 5}},
        ended=["bob", "nobody"],
        mint=[{"label": "link-1", "expires": NOW + 2}, {"label": "carol"}],
        settings={"cookie": "pass"},
    )
    lock, minted = built(raw)
    assert lock.id == lock_of()[0].id
    assert lock.now() == NOW
    assert (lock.home, lock.secure, lock.settings.cookie) == (HOME, True, "pass")
    assert lock.login("alice", "pw") is lock.entries[P("alice")]
    bob = lock.entries[L("bob")]
    assert (bob.kind, bob.key, bob.host, bob.path, bob.expires, bob.used, bob.spent, bob.uses, bob.ended) == (
        LINK, digest("k"), "a.foo.example.com", "/x", NOW + 1, 5, 1, 1, True,
    )  # fmt: skip
    assert [label for label, _ in minted] == ["link-1", "carol"]
    assert lock.link(minted[0][1]) is lock.entries[L("link-1")]
    assert lock.entries[L("link-1")].expires == NOW + 2
    carol = lock.entries[L("carol")]
    assert (carol.expires, carol.host, carol.path, carol.uses) == (None, "", "/", 1)


def test_a_lock_takes_links_with_little_said() -> None:
    lock, _ = built({"secret": SECRET_TEXT, "links": {"bob": {"key": digest("k")}}})
    bob = lock.entries[L("bob")]
    assert (bob.host, bob.path, bob.expires, bob.used, bob.spent, bob.uses) == ("", "/", None, None, 0, 1)
    assert built({"secret": SECRET_TEXT, "mint": [{"label": "x"}]}, on_domain=True)[0].on_domain


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ([], "a lock has the wrong type"),
        ({}, "the lock's secret has the wrong type"),
        ({"secret": 1}, "the lock's secret has the wrong type"),
        ({"secret": base64.urlsafe_b64encode(bytes(31)).decode()}, "the lock's secret is too short"),
        (spec(settings={"path": 1}), "lock setting 'path' has the wrong type"),
        (spec(settings={"path": "x", "cookie": " "}),
         "lock setting 'path': expected a path like /_wildburrow/login, got 'x'; "
         "lock setting 'cookie': ' ' can't be a cookie name"),
        (spec(users=[]), "the lock's users has the wrong type"),
        (spec(users={"a b": "pw"}), "'a b' can't name a login: use 1-64 letters, digits and . _ @ -"),
        (spec(users={"x" * 65: "pw"}), f"'{'x' * 65}' can't name a login: use 1-64 letters, digits and . _ @ -"),
        (spec(users={"alice": 1}), "a password has the wrong type"),
        (spec(links=[]), "the lock's links has the wrong type"),
        (spec(links={"bob": []}), "a link has the wrong type"),
        (spec(links={"bob": {}}), "a link's key has the wrong type"),
        (spec(links={"bob": {"key": "k"}}), "a link's key must be its digest"),
        (spec(links={"bob": {"key": digest("k").upper()}}), "a link's key must be its digest"),
        (spec(links={"bob": {"key": digest("k"), "host": 1}}), "a link's host has the wrong type"),
        (spec(links={"bob": {"key": digest("k"), "path": 1}}), "a link's path has the wrong type"),
        (spec(links={"bob": {"key": digest("k"), "path": "//x"}}), "'//x' isn't a path a link can land on"),
        (spec(links={"bob": {"key": digest("k"), "expires": "1"}}), "a link's expiry has the wrong type"),
        (spec(links={"bob": {"key": digest("k"), "used": True}}), "a link's use has the wrong type"),
        (spec(links={"bob": {"key": digest("k"), "spent": "1"}}), "a link's uses so far has the wrong type"),
        (spec(links={"bob": {"key": digest("k"), "uses": 0}}), "a link must be usable at least once"),
        (spec(links={"bob": {"key": digest("k"), "uses": "any"}}), "a link's uses has the wrong type"),
        (spec(counts=[]), "the lock's login counts has the wrong type"),
        (spec(counts={"password:alice": 1}), "a login count has the wrong type"),
        (spec(counts={"password:alice": {"logins": "1"}}), "a login count has the wrong type"),
        (spec(counts={"password:alice": {"seen": "now"}}), "when a login was last seen has the wrong type"),
        (spec(ended={}), "the lock's ended logins has the wrong type"),
        (spec(ended=[1]), "an ended login has the wrong type"),
        (spec(mint={}), "the links to mint has the wrong type"),
        (spec(mint=["x"]), "a link to mint has the wrong type"),
        (spec(mint=[{}]), "a lock label has the wrong type"),
        (spec(mint=[{"label": "x"}, {"label": "x"}]), "'x' names two logins"),
        (spec(mint=[{"label": "x", "uses": -1}]), "a link must be usable at least once"),
        (spec(mint=[{"label": "x", "expires": 1.5}]), "a link's expiry has the wrong type"),
        ({"secret": SECRET_TEXT}, "a lock needs a password or a link"),
        ({"secret": SECRET_TEXT, "users": {}, "links": {}, "mint": []}, "a lock needs a password or a link"),
    ],
)  # fmt: skip
def test_a_lock_asked_for_wrongly_is_refused(raw: Any, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        built(raw)


def test_a_secret_that_isnt_base64_is_refused() -> None:
    for secret in ("!!!!", "a", "AAAA=AAA"):
        with pytest.raises(ValueError, match=r"^the lock's secret isn't base64$"):
            built(spec(secret=secret))
    assert built(spec(secret=SECRET_TEXT.rstrip("=")))[0].id == lock_of()[0].id


def server_env(**changes: str) -> dict[str, str]:
    return {f"WILDBURROW_LOCK_{key.upper()}": value for key, value in changes.items()}


def test_the_operator_sets_every_locks_defaults() -> None:
    assert locking({}) == Locking()
    loaded = locking(server_env(path="/in", confirm_links="false", attempts="3", code_expires="1m", page="<p>"))
    assert loaded == Locking(LockSettings(path="/in", confirm_links=False, page="<p>"), 3, 60)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"code_expires": "soon"}, "WILDBURROW_LOCK_CODE_EXPIRES: expected a duration like 30m, 12h or 7d, got 'soon'"),
        ({"attempts": "0"}, "WILDBURROW_LOCK_ATTEMPTS: must be at least 1"),
        ({"cookie": "a b"}, "WILDBURROW_LOCK_COOKIE: 'a b' can't be a cookie name"),
        (
            {"user_header": "Host", "attempts": "-1"},
            "WILDBURROW_LOCK_USER_HEADER: 'Host' can't be a header of its own; "
            "WILDBURROW_LOCK_ATTEMPTS: must be at least 1",
        ),
    ],
)  # fmt: skip
def test_the_operators_mistakes_stop_the_server(changes: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError) as error:
        locking(server_env(**changes))
    assert str(error.value) == message


def test_one_attempt_is_enough() -> None:
    assert locking(server_env(attempts="1")).attempts == 1


def locked_tunnel(identity: Identity = ALICE) -> FakeTunnel:
    return FakeTunnel(identity)


async def test_a_lock_is_homed_on_its_first_plain_name(ctx: ServerContext) -> None:
    tunnel = locked_tunnel()
    minted = ctx.lock(tunnel, ["*.foo", "bad name", "foo", "bar"], spec(mint=[{"label": "x"}]), Changes())
    lock = tunnel.lock
    assert lock is not None
    assert (lock.home, lock.on_domain, lock.secure) == ("foo.example.com", False, False)

    assert ctx.locks == {lock.id: lock}
    [link] = minted
    assert link["label"] == "x"
    assert link["url"].startswith("http://foo.example.com/_wildburrow/login/link/")


async def test_a_name_too_long_for_the_domain_isnt_a_home(ctx: ServerContext) -> None:
    tunnel = locked_tunnel()
    long = ".".join(["a" * 60] * 4)
    assert len(f"{long}.example.com") > 253 >= len(f"{long}.None")
    ctx.lock(tunnel, [long, "foo"], spec(), Changes())
    assert tunnel.lock is not None
    assert tunnel.lock.home == "foo.example.com"


async def test_a_lock_with_only_wildcards_is_homed_on_the_domain(ctx: ServerContext) -> None:
    tunnel = locked_tunnel()
    ctx.lock(tunnel, ["*.foo"], spec(), Changes())
    assert tunnel.lock is not None
    assert (tunnel.lock.home, tunnel.lock.on_domain) == ("example.com", True)


async def test_a_tunnel_is_locked_once(ctx: ServerContext) -> None:
    tunnel = locked_tunnel()
    ctx.lock(tunnel, ["foo"], spec(), Changes())
    first = tunnel.lock
    with pytest.raises(BindRejected, match=r"^this tunnel is already locked$"):
        ctx.lock(tunnel, ["foo"], spec(), Changes())
    assert tunnel.lock is first


async def test_a_lock_the_context_cant_build_is_refused(ctx: ServerContext) -> None:
    tunnel = locked_tunnel()
    with pytest.raises(BindRejected, match=r"^lock: a lock needs a password or a link$"):
        ctx.lock(tunnel, ["foo"], {"secret": SECRET_TEXT}, Changes())
    assert (tunnel.lock, ctx.locks) == (None, {})


async def test_unlocking_lets_go_only_of_its_own_lock(ctx: ServerContext) -> None:
    old, new = locked_tunnel(), locked_tunnel()
    ctx.lock(old, ["foo"], spec(), Changes())
    ctx.lock(new, ["foo"], spec(), Changes())
    ctx.unlock(old)
    assert ctx.locks == {new.lock.id: new.lock}
    ctx.unlock(new)
    assert ctx.locks == {}
    ctx.unlock(locked_tunnel())


def bound(ctx: ServerContext, tunnel: FakeTunnel, *names: str) -> None:
    for name in names:
        wildcard = name.startswith("*.")
        ctx.registry.bind(Name(tuple(name.removeprefix("*.").split(".")), wildcard), tunnel)


async def test_links_are_minted_only_for_your_own_locked_tunnels(ctx: ServerContext) -> None:
    mine, theirs, open_tunnel = locked_tunnel(), locked_tunnel(BOB), locked_tunnel()
    ctx.lock(mine, ["foo"], spec(), Changes())
    ctx.lock(theirs, ["bar"], spec(), Changes())
    bound(ctx, mine, "foo", "*.foo")
    bound(ctx, theirs, "bar")
    bound(ctx, open_tunnel, "baz")
    minted = ctx.mint(ALICE, {"url": "https://a.foo.example.com:8443/x?y=1"})
    assert minted["label"] == "link-1"
    assert mine.lock.entries[L("link-1")].host == "a.foo.example.com"
    assert mine.lock.entries[L("link-1")].path == "/x?y=1"
    assert mine.lock.entries[L("link-1")].uses == 1
    assert ctx.mint(ALICE, {"url": "foo.example.com", "label": "bob", "expires": NOW})["label"] == "bob"
    assert (mine.lock.entries[L("bob")].path, mine.lock.entries[L("bob")].expires) == ("/", NOW)
    assert ctx.mint(ALICE, {"url": "foo.example.com", "expires": "soon"})["label"] == "link-2"
    assert ctx.mint(ALICE, {"url": "http://foo.example.com/x://y"})["label"] == "link-3"
    assert mine.lock.entries[L("link-3")].path == "/x://y"
    assert mine.lock.entries[L("link-2")].expires is None
    for url, error in [
        ("bar.example.com", "no locked tunnel of yours serves 'bar.example.com'"),
        ("baz.example.com", "no locked tunnel of yours serves 'baz.example.com'"),
        ("nowhere.org", "no locked tunnel of yours serves 'nowhere.org'"),
        ("https://", "no locked tunnel of yours serves 'https://'"),
        ("foo.example.com//x", "a link can't land on '//x'"),
    ]:
        assert ctx.mint(ALICE, {"url": url}) == {"error": error}
    assert ctx.mint(ALICE, {"url": "foo.example.com", "label": "bob"}) == {
        "error": "'bob' is taken or can't name a login"
    }
    assert ctx.mint(ALICE, {"url": "foo.example.com", "label": "a b"}) == {
        "error": "'a b' is taken or can't name a login"
    }


async def test_logins_and_ending_them_reach_only_your_own_tunnels(ctx: ServerContext) -> None:
    mine, theirs = locked_tunnel(), locked_tunnel(BOB)
    ctx.lock(mine, ["foo"], spec(), Changes())
    ctx.lock(theirs, ["bar"], spec(), Changes())
    bound(ctx, mine, "foo", "*.foo")
    bound(ctx, theirs, "bar")
    [listed] = ctx.logins(ALICE)
    assert listed["names"] == ["foo", "*.foo"]
    assert [entry["who"] for entry in listed["logins"]] == ["alice"]
    assert ctx.end_login(ALICE, "alice") == {"who": "alice", "ended": [["foo", "*.foo"]]}
    assert ctx.end_login(ALICE, "alice") == {"who": "alice", "ended": []}
    assert theirs.lock.login("alice", "pw") is not None


def test_one_name_can_have_a_password_and_a_link() -> None:
    lock, _, changes = lock_of()
    password = lock.add_password("anil", "pw")
    key = lock.mint("anil", "", "/", None, 1)
    link = lock.entries[L("anil")]
    assert lock.login("anil", "pw") is password
    assert lock.link(key) is link
    assert (password.label, link.label) == ("anil", "anil")
    assert lock.admitted(HOME, lock.cookie(HOME, link, 0)) == (link, 0)
    assert lock.admitted(HOME, lock.cookie(HOME, password, 0)) == (password, 0)
    assert [entry["who"] for entry in lock.listing()] == ["anil", "anil"]
    assert lock.end("anil")
    assert (password.ended, link.ended) == (True, True)
    assert changes[-1]["ended"] == [P("anil"), L("anil")]


def test_ending_a_password_keeps_a_cookie_from_the_link_working() -> None:
    lock, _, _ = lock_of()
    lock.add_password("anil", "pw")
    lock.mint("anil", "", "/", None, 1)
    link = lock.entries[L("anil")]
    cookie = lock.cookie(HOME, link, 0)
    lock.entries[P("anil")].ended = True
    assert lock.admitted(HOME, cookie) == (link, 0)


@pytest.mark.parametrize("uses", [1, 3, None])
def test_a_link_works_as_often_as_it_may(uses: int | None) -> None:
    lock, clock, _ = lock_of()
    key = lock.mint("bob", "", "/", None, uses)
    entry = lock.entries[L("bob")]
    for spent in range(1, 6):
        if uses is not None and spent > uses:
            assert lock.link(key) is None
            continue
        assert lock.link(key) is entry
        clock.now += 1
        lock.spend(entry)
        assert (entry.spent, entry.used, entry.logins) == (spent, int(clock.now), spent)


def test_sightings_reach_the_client_no_more_than_once_a_minute() -> None:
    lock, clock, changes = lock_of()
    entry = lock.add_password("alice", "pw")
    lock.logged_in(entry)
    assert changes[-1]["counts"] == {P("alice"): {"logins": 1, "seen": NOW}}
    told = len(changes)
    clock.now = NOW + SEEN_EVERY - 1
    lock.seen(entry)
    assert (len(changes), entry.seen) == (told, NOW + SEEN_EVERY - 1)
    clock.now = NOW + SEEN_EVERY
    lock.seen(entry)
    assert len(changes) == told + 1
    assert changes[-1]["counts"] == {P("alice"): {"logins": 1, "seen": NOW + SEEN_EVERY}}
    lock.seen(entry)
    assert len(changes) == told + 1


def test_a_reconnect_brings_back_counts_and_what_ended() -> None:
    raw = spec(
        users={"alice": "pw", "bob": "pw"},
        links={
            "bob": {"key": digest("k"), "used": NOW, "spent": 2, "uses": 3},
            "old": {"key": digest("o"), "used": NOW},
            "fresh": {"key": digest("f"), "uses": None},
        },
        ended=[L("bob"), "nobody"],
        counts={
            P("alice"): {"logins": 4, "seen": NOW - 5}, P("bob"): {"logins": 2}, L("old"): {"seen": NOW},
            L("bob"): {}, "link:nobody": {"logins": 1},
        },
    )  # fmt: skip
    lock, _ = built(raw)
    assert lock.state()["counts"] == {
        P("alice"): {"logins": 4, "seen": NOW - 5},
        P("bob"): {"logins": 2, "seen": None},
        L("old"): {"logins": 0, "seen": NOW},
    }
    alice, bob = lock.entries[P("alice")], lock.entries[L("bob")]
    assert (alice.logins, alice.seen, alice.told, alice.ended) == (4, NOW - 5, NOW - 5, False)
    assert (bob.spent, bob.uses, bob.logins, bob.seen, bob.ended) == (2, 3, 0, None, True)
    assert not lock.entries[P("bob")].ended
    assert (lock.entries[L("old")].spent, lock.entries[L("old")].uses) == (1, 1)
    assert (lock.entries[L("fresh")].spent, lock.entries[L("fresh")].uses) == (0, None)


def test_a_client_before_0_5_0_ends_logins_by_label() -> None:
    lock, _ = built(spec(users={"anil": "pw"}, links={"anil": {"key": digest("k")}}, ended=["anil"]))
    assert all(entry.ended for entry in lock.entries.values())


def test_links_minted_with_the_lock_work_as_often_as_asked() -> None:
    lock, minted = built(spec(mint=[{"label": "a", "uses": 2}, {"label": "b", "uses": None}, {"label": "c"}]))
    assert [lock.entries[L(label)].uses for label, _ in minted] == [2, None, 1]


async def test_a_minted_link_may_share_a_passwords_name_and_work_as_often_as_asked(ctx: ServerContext) -> None:
    mine = locked_tunnel()
    ctx.lock(mine, ["foo"], spec(), Changes())
    bound(ctx, mine, "foo")
    assert ctx.mint(ALICE, {"url": "foo.example.com", "label": "alice", "uses": 3})["label"] == "alice"
    assert mine.lock.entries[L("alice")].uses == 3
    assert ctx.mint(ALICE, {"url": "foo.example.com", "uses": None})["label"] == "link-1"
    assert mine.lock.entries[L("link-1")].uses is None
    assert ctx.mint(ALICE, {"url": "foo.example.com", "label": "alice"}) == {
        "error": "'alice' is taken or can't name a login"
    }
    for uses in (0, -1, "2", True):
        assert ctx.mint(ALICE, {"url": "foo.example.com", "uses": uses}) == {
            "error": "a link must be usable at least once"
        }
