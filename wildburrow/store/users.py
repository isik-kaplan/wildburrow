"""Users as the database keeps them: read once at start, and every change written at once, with who made it."""

from dataclasses import dataclass, field
from typing import Any

from wildburrow.store.database import MEMORY, Database

SETTINGS, TOKEN, DATABASE = "settings", "token", "database"

USERS = "SELECT id, name, alias, source, admin, password_hash, gone_at IS NOT NULL FROM users"
KEYS = "SELECT user_id, public_key, fingerprint, label FROM user_keys WHERE removed_at IS NULL"
USER = "INSERT INTO users (id, name, source, created_at) VALUES (?, ?, ?, ?)"
SOURCE = "UPDATE users SET source = ?, gone_at = NULL WHERE id = ?"
GONE = "UPDATE users SET gone_at = ? WHERE id = ?"
BACK = "UPDATE users SET gone_at = NULL WHERE id = ?"
ADMIN = "UPDATE users SET admin = ? WHERE id = ?"
REMOVED = "UPDATE users SET gone_at = ?, admin = 0, password_hash = NULL, password_changed_at = NULL WHERE id = ?"
# What joining sets, in one change: an alias and a password, each kept as it was when not given.
JOINED = (
    "UPDATE users SET alias = coalesce(?1, alias), password_hash = coalesce(?2, password_hash), "
    "password_changed_at = CASE WHEN ?2 IS NULL THEN password_changed_at ELSE ?3 END WHERE id = ?4"
)
KEY = "INSERT INTO user_keys (id, user_id, fingerprint, public_key, label, added_at) VALUES (?, ?, ?, ?, ?, ?)"
KEYS_GONE = "UPDATE user_keys SET removed_at = ? WHERE user_id = ? AND removed_at IS NULL"
INVITE = (
    "INSERT INTO invites (id, user_id, digest, created_at, expires_at, created_by_command_id) VALUES (?, ?, ?, ?, ?, ?)"
)
INVITES_ENDED = "UPDATE invites SET ended_at = ? WHERE user_id = ? AND used_at IS NULL AND ended_at IS NULL"
OPEN_INVITE = (
    "SELECT invites.id, users.id FROM invites JOIN users ON users.id = user_id "
    "WHERE digest = ? AND used_at IS NULL AND ended_at IS NULL AND expires_at > ?"
)
INVITE_USED = "UPDATE invites SET used_at = ? WHERE id = ?"
PENDING = "SELECT user_id, max(expires_at) FROM invites WHERE used_at IS NULL AND ended_at IS NULL GROUP BY user_id"


@dataclass(slots=True)
class User:
    id: int
    name: str
    source: str
    alias: str | None = None
    admin: bool = False
    # argon2, with its salt in it.
    password: str | None = None
    # Each key's OpenSSH line, and its fingerprint and the device it's on.
    keys: dict[str, tuple[str, str]] = field(default_factory=dict)
    gone: bool = False


type Write = tuple[str, tuple[Any, ...]]


class UserStore:
    """The users table and those beside it; with no database, as in tests, nothing is kept."""

    def __init__(self, database: Database | None) -> None:
        self._database = database

    @property
    def memory(self) -> bool:
        """Whether users are lost when the server stops, the database being in memory."""
        return in_memory(self._database)

    def next_id(self, table: str) -> int:
        return 0 if self._database is None else self._database.next_id(table)

    def now(self) -> int:
        return 0 if self._database is None else self._database.now()

    async def load(self) -> list[User]:
        if self._database is None:
            return []
        found = {
            row[0]: User(row[0], row[1], row[3], row[2], bool(row[4]), row[5], gone=bool(row[6]))
            for row in await self._database.read(USERS)
        }
        for user_id, public_key, fingerprint, label in await self._database.read(KEYS):
            found[user_id].keys[public_key] = (fingerprint, label)
        return list(found.values())

    async def invite_for(self, digest: str) -> tuple[int, int] | None:
        """The open invite `digest` is of, and whose it is."""
        if self._database is None:
            return None
        found = await self._database.read(OPEN_INVITE, digest, self.now())
        return found[0] if found else None

    async def pending(self) -> dict[int, int]:
        """When each user's open invite runs out."""
        if self._database is None:
            return {}
        return dict(await self._database.read(PENDING))

    async def write(self, context: dict[str, Any], *writes: Write) -> None:
        if self._database is not None:
            await self._database.write_now(context, *writes)


def in_memory(database: Database | None) -> bool:
    return database is None or database.storage.path == MEMORY
