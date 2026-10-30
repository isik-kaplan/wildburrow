"""Everyone who can log in, as users: those the settings name, signed tokens' holders, and those invited at runtime."""

import hashlib
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import asyncssh

from wildburrow.auth.base import USER_NAME
from wildburrow.config import PREFIX, ConfigError
from wildburrow.core.types import Identity
from wildburrow.store import users as store
from wildburrow.store.users import DATABASE, SETTINGS, TOKEN, User, UserStore, Write

INVITE_PREFIX = "wbi_"
INVITE_BYTES = 24
# How long an invite can wait to be used, unless the admin says otherwise.
INVITE_SECONDS = 7 * 24 * 3600
BAD_NAME = "{!r} can't be a name: 1-64 characters, with no spaces or colons"


class UserError(Exception):
    """Why a change to users was refused, as the one asking is told."""


@dataclass(frozen=True, slots=True)
class Key:
    """A key someone joins with: its OpenSSH line, its fingerprint, and the device it's on."""

    line: str
    fingerprint: str
    label: str


def digest(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def public_data(line: str) -> bytes:
    return asyncssh.import_public_key(line).public_data


class Users:
    """Users kept in memory, the server being the only one writing them, and written through to the database at once.

    A name is one source's: the settings', a signed token holder's or the database's. The settings decide their users;
    only database users take a password, keys, an alias or the admin flag from here.
    """

    def __init__(self, store: UserStore) -> None:
        self._store = store
        self._by_name: dict[str, User] = {}
        self._aliases: dict[str, User] = {}
        # Each database key's public data, and whose it is.
        self._keys: dict[bytes, User] = {}
        # Names of database users made admins here, kept live for the admin rules.
        self.admins: set[str] = set()
        # Fingerprints the settings let in, which no one can join with.
        self._settings_keys: frozenset[str] = frozenset()
        self.run_id: int | None = None
        # Whether users invited here are lost when the server stops.
        self.memory = store.memory

    def _context(self, context: dict[str, Any]) -> dict[str, Any]:
        return {"run": self.run_id, **context}

    def _add(self, user: User) -> None:
        self._by_name[user.name] = user
        if user.alias is not None:
            self._aliases[user.alias] = user
        for line in user.keys:
            self._keys[public_data(line)] = user
        if user.admin:
            self.admins.add(user.name)

    def _database_name(self, name: str) -> bool:
        """Whether `name` is a database user's, as their name or alias, removed or not."""
        user = self._by_name.get(name)
        return (user is not None and user.source == DATABASE) or name in self._aliases

    async def open(self, names: Iterable[str], settings_keys: Iterable[str]) -> None:
        """Loads users, and brings those the settings name in line: added, back, or gone from the settings."""
        for user in await self._store.load():
            self._add(user)
        self._settings_keys = frozenset(settings_keys)
        names = set(names)
        if clashes := sorted(filter(self._database_name, names)):
            raise ConfigError(
                f"{', '.join(clashes)}: in the settings and a database user's too; the settings decide their own "
                f"users, so take the name out of the {PREFIX}AUTH_* settings or remove the database user"
            )
        writes: list[Write] = []
        now = self._store.now()
        for name in sorted(names):
            if (user := self._by_name.get(name)) is None:
                user = User(self._store.next_id("users"), name, SETTINGS)
                writes.append((store.USER, (user.id, name, SETTINGS, now)))
                self._add(user)
            elif user.source != SETTINGS or user.gone:
                writes.append((store.SOURCE, (SETTINGS, user.id)))
                user.source, user.gone = SETTINGS, False
        for user in self._by_name.values():
            if user.source == SETTINGS and user.name not in names and not user.gone:
                writes.append((store.GONE, (now, user.id)))
                user.gone = True
        if writes:
            await self._store.write(self._context({"by": "settings"}), *writes)

    # Logging in

    def id_of(self, identity: Identity) -> int | None:
        user = self._by_name.get(identity.user)
        return None if user is None else user.id

    def password(self, name: str) -> tuple[str, str] | None:
        """A database user's name and password hash, by their name or alias."""
        user = self._aliases.get(name) or self._by_name.get(name)
        if user is None or user.source != DATABASE or user.gone or user.password is None:
            return None
        return user.name, user.password

    def key(self, data: bytes) -> tuple[str, str, str] | None:
        """The database user a key logs in, the key's fingerprint, and the device it's on."""
        user = self._keys.get(data)
        if user is None:
            return None
        fingerprint, label = next(found for line, found in user.keys.items() if public_data(line) == data)
        return user.name, fingerprint, label

    async def admit(self, identity: Identity) -> bool:
        """Whether `identity`, which its credential let in, may log in as its user; a signed token's holder is added."""
        name = identity.user
        if name in self._aliases:
            # An alias only ever stands for its own user, logging in with that user's password.
            return False
        user = self._by_name.get(name)
        if identity.method != "token":
            # The settings' users are all here from the start, and the database's log in with their own logins.
            return user is None or not user.gone
        if user is not None and (user.source == DATABASE or not user.gone):
            # A token signed for a database user's name isn't theirs.
            return user.source != DATABASE
        if user is None:
            user = User(self._store.next_id("users"), name, TOKEN)
            write: Write = (store.USER, (user.id, name, TOKEN, self._store.now()))
            self._add(user)
        else:
            write = (store.SOURCE, (TOKEN, user.id))
            user.source, user.gone = TOKEN, False
        await self._store.write(self._context({"by": "token", "identity": identity.subject}), write)
        return True

    # Changes, by an admin

    async def invite(
        self, name: str, context: dict[str, Any], seconds: int = INVITE_SECONDS, command: int | None = None
    ) -> tuple[str, int]:
        """A one-time code that lets someone set up their own login as `name`, and when it runs out."""
        if not USER_NAME.fullmatch(name):
            raise UserError(BAD_NAME.format(name))
        if seconds < 1:
            raise UserError("an invite has to last at least a second")
        user = self._by_name.get(name)
        if user is not None and user.source != DATABASE:
            raise UserError(f"{name} comes from the settings: change them there")
        if name in self._aliases:
            raise UserError(f"{name} is another user's alias")
        code = INVITE_PREFIX + secrets.token_urlsafe(INVITE_BYTES)
        now = self._store.now()
        writes: list[Write] = []
        if user is None:
            user = User(self._store.next_id("users"), name, DATABASE)
            writes.append((store.USER, (user.id, name, DATABASE, now)))
            self._add(user)
        elif user.gone:
            writes.append((store.BACK, (user.id,)))
            user.gone = False
        expires = now + seconds
        writes += [
            (store.INVITES_ENDED, (now, user.id)),
            (store.INVITE, (self._store.next_id("invites"), user.id, digest(code), now, expires, command)),
        ]
        await self._store.write(self._context(context), *writes)
        return code, expires

    async def join(
        self, code: str, password: str | None, key: Key | None, alias: str | None, context: dict[str, Any]
    ) -> str:
        """Sets up the login an invite was for, spending it; the user's name. `password` comes hashed."""
        if password is None and key is None:
            raise UserError("joining sets a password, a key, or both")
        found = await self._store.invite_for(digest(code))
        if found is None:
            raise UserError("that invite can't be used: it was used, ended or ran out")
        invite, user_id = found
        user = next(user for user in self._by_name.values() if user.id == user_id)
        if alias is not None:
            if not USER_NAME.fullmatch(alias):
                raise UserError(BAD_NAME.format(alias))
            if alias != user.alias and (alias in self._by_name or alias in self._aliases):
                raise UserError(f"{alias} is taken")
        if key is not None and (
            key.fingerprint in self._settings_keys or self._keys.get(public_data(key.line), user) is not user
        ):
            raise UserError("that key already logs someone else in")
        now = self._store.now()
        writes: list[Write] = [(store.INVITE_USED, (now, invite)), (store.JOINED, (alias, password, now, user.id))]
        if key is not None and key.line not in user.keys:
            writes.append(
                (store.KEY, (self._store.next_id("user_keys"), user.id, key.fingerprint, key.line, key.label, now))
            )
        await self._store.write(self._context({**context, "user": user.name}), *writes)
        if alias is not None:
            if user.alias is not None:
                del self._aliases[user.alias]
            user.alias = alias
            self._aliases[alias] = user
        if password is not None:
            user.password = password
        if key is not None:
            user.keys[key.line] = (key.fingerprint, key.label)
            self._keys[public_data(key.line)] = user
        return user.name

    def identities(self, name: str) -> list[Identity]:
        """Every way a database user logs in, as the identity it logs them in as."""
        user = self._by_name[name]
        found = [Identity(name, "password", name)] if user.password is not None else []
        return found + [
            Identity(f"{name}@{label}", "key", fingerprint, owner=name) for fingerprint, label in user.keys.values()
        ]

    def _database_user(self, name: str) -> User:
        user = self._by_name.get(name)
        if user is None or user.gone:
            raise UserError(f"no user {name}")
        if user.source != DATABASE:
            raise UserError(f"{name} comes from the settings: change them there")
        return user

    async def set_admin(self, name: str, admin: bool, context: dict[str, Any]) -> bool:
        """Makes a database user an admin or not; whether that changed anything."""
        user = self._database_user(name)
        if user.admin == admin:
            return False
        await self._store.write(self._context(context), (store.ADMIN, (int(admin), user.id)))
        user.admin = admin
        if admin:
            self.admins.add(name)
        else:
            self.admins.discard(name)
        return True

    async def remove(self, name: str, context: dict[str, Any]) -> None:
        """Stops a database user logging in: their password, keys and open invites go; their history stays."""
        user = self._database_user(name)
        now = self._store.now()
        await self._store.write(
            self._context(context),
            (store.REMOVED, (now, user.id)),
            (store.KEYS_GONE, (now, user.id)),
            (store.INVITES_ENDED, (now, user.id)),
        )
        user.gone, user.admin, user.password = True, False, None
        self.admins.discard(name)
        # Each key a user has logs in only them, the database's index sees to it.
        for line in user.keys:
            del self._keys[public_data(line)]
        user.keys.clear()

    async def listing(self) -> list[dict[str, Any]]:
        """Every user, for an admin: where they come from and how they log in, never a hash."""
        pending = await self._store.pending()
        return [
            {
                "name": user.name,
                "alias": user.alias,
                "source": user.source,
                "admin": user.admin,
                "password": user.password is not None,
                "keys": sorted(label for _, label in user.keys.values()),
                "invited_until": pending.get(user.id),
                "gone": user.gone,
            }
            for user in sorted(self._by_name.values(), key=lambda user: user.name)
        ]
