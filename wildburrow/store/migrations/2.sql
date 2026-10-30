-- Version 2: users, and a record of every change to who may log in.
--
-- A user is a name, and everyone who logs in is one. Users from the settings (a password line, a key's comment, a
-- token hash's name) and signed tokens' holders are mirrored here as the server meets them; the settings decide them.
-- Users invited at runtime live only here. Password hashes are argon2, salted in the hash itself; invite codes are kept
-- only as digests.

-- ---------------------------------------------------------------------------------------------------------------------
-- Users

CREATE TABLE users (
    id                  INTEGER PRIMARY KEY,
    name                TEXT    NOT NULL UNIQUE,
    -- A second name an invited user logs in with.
    alias               TEXT    UNIQUE,
    -- 'settings' (a password line, a key's comment or a token hash's name), 'token' (a signed token's holder) or
    -- 'database' (invited). Only database users take an alias, a password, keys or the admin flag from here.
    source              TEXT    NOT NULL CHECK (source IN ('settings', 'token', 'database')),
    admin               INTEGER NOT NULL DEFAULT 0 CHECK (admin IN (0, 1)),
    password_hash       TEXT    CHECK (password_hash IS NULL OR password_hash LIKE '$argon2%'),
    password_changed_at INTEGER,
    created_at          INTEGER NOT NULL,
    -- A settings user no longer in the settings, or a database user removed: kept for the history pointing at it, but
    -- it can't log in.
    gone_at             INTEGER,
    CHECK (source = 'database' OR (alias IS NULL AND admin = 0 AND password_hash IS NULL)),
    CHECK ((password_hash IS NULL) = (password_changed_at IS NULL))
) STRICT;

-- A name and an alias never collide, whoever writes them.
CREATE TRIGGER users_names_apart_on_insert BEFORE INSERT ON users
WHEN NEW.alias = NEW.name OR EXISTS (SELECT 1 FROM users WHERE name = NEW.alias OR alias = NEW.name)
BEGIN
    SELECT RAISE(ABORT, 'a user''s name and another''s alias collide');
END;
CREATE TRIGGER users_names_apart_on_update BEFORE UPDATE OF name, alias ON users
WHEN NEW.alias = NEW.name
    OR EXISTS (SELECT 1 FROM users WHERE id != NEW.id AND (name = NEW.alias OR alias = NEW.name))
BEGIN
    SELECT RAISE(ABORT, 'a user''s name and another''s alias collide');
END;

-- Keys an invited user logs in with, added when they joined.
CREATE TABLE user_keys (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    fingerprint TEXT    NOT NULL,
    public_key  TEXT    NOT NULL,
    -- The device it's on, as its owner named it.
    label       TEXT    NOT NULL,
    added_at    INTEGER NOT NULL,
    removed_at  INTEGER
) STRICT;
CREATE INDEX user_keys_user ON user_keys (user_id);
-- A key logs in one user at a time; once removed, it can be joined with again.
CREATE UNIQUE INDEX user_keys_live ON user_keys (fingerprint) WHERE removed_at IS NULL;

-- One-time codes that let someone set up their own login as the user they were invited as.
CREATE TABLE invites (
    id                    INTEGER PRIMARY KEY,
    user_id               INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- sha256 of the code only the invited person is given.
    digest                TEXT    NOT NULL UNIQUE CHECK (length(digest) = 64),
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    used_at               INTEGER,
    -- Ended before it was used, by a newer invite or the user's removal.
    ended_at              INTEGER,
    created_by_command_id INTEGER REFERENCES commands (id) ON DELETE SET NULL,
    CHECK (expires_at > created_at)
) STRICT;
CREATE INDEX invites_user ON invites (user_id);

ALTER TABLE identities ADD COLUMN user_id INTEGER REFERENCES users (id) ON DELETE SET NULL;
CREATE INDEX identities_user ON identities (user_id);

-- ---------------------------------------------------------------------------------------------------------------------
-- Events: every change to the tables above, and to identities' users and tokens' denials, as a copy of the row after
-- it (before it, for a delete). Written by triggers, so a change made to the file by hand is recorded too.

-- Who made the change the server is writing, and from where: set right before its write and cleared right after, in
-- the same transaction, so a change with no context came from outside the server.
CREATE TABLE event_context (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    context TEXT    NOT NULL CHECK (json_valid(context))
) STRICT;

CREATE TABLE users_events (
    event_id            INTEGER PRIMARY KEY,
    at                  INTEGER NOT NULL,
    label               TEXT    NOT NULL CHECK (label IN ('insert', 'update', 'delete')),
    row_id              INTEGER NOT NULL,
    context             TEXT    CHECK (context IS NULL OR json_valid(context)),
    name                TEXT    NOT NULL,
    alias               TEXT,
    source              TEXT    NOT NULL,
    admin               INTEGER NOT NULL,
    -- Whether a password is set; never the hash, so no old hash outlives a change.
    password_set        INTEGER NOT NULL,
    password_changed_at INTEGER,
    created_at          INTEGER NOT NULL,
    gone_at             INTEGER
) STRICT;
CREATE INDEX users_events_row ON users_events (row_id, event_id);

CREATE TRIGGER users_inserted AFTER INSERT ON users BEGIN
    INSERT INTO users_events (at, label, row_id, context, name, alias, source, admin, password_set,
                              password_changed_at, created_at, gone_at)
    VALUES (unixepoch(), 'insert', NEW.id, (SELECT context FROM event_context), NEW.name, NEW.alias, NEW.source,
            NEW.admin, NEW.password_hash IS NOT NULL, NEW.password_changed_at, NEW.created_at, NEW.gone_at);
END;
CREATE TRIGGER users_updated AFTER UPDATE ON users
WHEN OLD.name IS NOT NEW.name OR OLD.alias IS NOT NEW.alias OR OLD.source IS NOT NEW.source
    OR OLD.admin IS NOT NEW.admin OR OLD.password_hash IS NOT NEW.password_hash
    OR OLD.password_changed_at IS NOT NEW.password_changed_at OR OLD.gone_at IS NOT NEW.gone_at
BEGIN
    INSERT INTO users_events (at, label, row_id, context, name, alias, source, admin, password_set,
                              password_changed_at, created_at, gone_at)
    VALUES (unixepoch(), 'update', NEW.id, (SELECT context FROM event_context), NEW.name, NEW.alias, NEW.source,
            NEW.admin, NEW.password_hash IS NOT NULL, NEW.password_changed_at, NEW.created_at, NEW.gone_at);
END;
CREATE TRIGGER users_deleted AFTER DELETE ON users BEGIN
    INSERT INTO users_events (at, label, row_id, context, name, alias, source, admin, password_set,
                              password_changed_at, created_at, gone_at)
    VALUES (unixepoch(), 'delete', OLD.id, (SELECT context FROM event_context), OLD.name, OLD.alias, OLD.source,
            OLD.admin, OLD.password_hash IS NOT NULL, OLD.password_changed_at, OLD.created_at, OLD.gone_at);
END;

CREATE TABLE user_keys_events (
    event_id    INTEGER PRIMARY KEY,
    at          INTEGER NOT NULL,
    label       TEXT    NOT NULL CHECK (label IN ('insert', 'update', 'delete')),
    row_id      INTEGER NOT NULL,
    context     TEXT    CHECK (context IS NULL OR json_valid(context)),
    user_id     INTEGER NOT NULL,
    fingerprint TEXT    NOT NULL,
    public_key  TEXT    NOT NULL,
    key_label   TEXT    NOT NULL,
    added_at    INTEGER NOT NULL,
    removed_at  INTEGER
) STRICT;
CREATE INDEX user_keys_events_row ON user_keys_events (row_id, event_id);

CREATE TRIGGER user_keys_inserted AFTER INSERT ON user_keys BEGIN
    INSERT INTO user_keys_events (at, label, row_id, context, user_id, fingerprint, public_key, key_label, added_at,
                                  removed_at)
    VALUES (unixepoch(), 'insert', NEW.id, (SELECT context FROM event_context), NEW.user_id, NEW.fingerprint,
            NEW.public_key, NEW.label, NEW.added_at, NEW.removed_at);
END;
CREATE TRIGGER user_keys_updated AFTER UPDATE ON user_keys
WHEN OLD.user_id IS NOT NEW.user_id OR OLD.fingerprint IS NOT NEW.fingerprint OR OLD.public_key IS NOT NEW.public_key
    OR OLD.label IS NOT NEW.label OR OLD.added_at IS NOT NEW.added_at OR OLD.removed_at IS NOT NEW.removed_at
BEGIN
    INSERT INTO user_keys_events (at, label, row_id, context, user_id, fingerprint, public_key, key_label, added_at,
                                  removed_at)
    VALUES (unixepoch(), 'update', NEW.id, (SELECT context FROM event_context), NEW.user_id, NEW.fingerprint,
            NEW.public_key, NEW.label, NEW.added_at, NEW.removed_at);
END;
CREATE TRIGGER user_keys_deleted AFTER DELETE ON user_keys BEGIN
    INSERT INTO user_keys_events (at, label, row_id, context, user_id, fingerprint, public_key, key_label, added_at,
                                  removed_at)
    VALUES (unixepoch(), 'delete', OLD.id, (SELECT context FROM event_context), OLD.user_id, OLD.fingerprint,
            OLD.public_key, OLD.label, OLD.added_at, OLD.removed_at);
END;

-- An invite's digest stays out: it's the one thing a copy of this file could be checked against.
CREATE TABLE invites_events (
    event_id              INTEGER PRIMARY KEY,
    at                    INTEGER NOT NULL,
    label                 TEXT    NOT NULL CHECK (label IN ('insert', 'update', 'delete')),
    row_id                INTEGER NOT NULL,
    context               TEXT    CHECK (context IS NULL OR json_valid(context)),
    user_id               INTEGER NOT NULL,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,
    used_at               INTEGER,
    ended_at              INTEGER,
    created_by_command_id INTEGER
) STRICT;
CREATE INDEX invites_events_row ON invites_events (row_id, event_id);

CREATE TRIGGER invites_inserted AFTER INSERT ON invites BEGIN
    INSERT INTO invites_events (at, label, row_id, context, user_id, created_at, expires_at, used_at, ended_at,
                                created_by_command_id)
    VALUES (unixepoch(), 'insert', NEW.id, (SELECT context FROM event_context), NEW.user_id, NEW.created_at,
            NEW.expires_at, NEW.used_at, NEW.ended_at, NEW.created_by_command_id);
END;
CREATE TRIGGER invites_updated AFTER UPDATE ON invites
WHEN OLD.user_id IS NOT NEW.user_id OR OLD.digest IS NOT NEW.digest OR OLD.created_at IS NOT NEW.created_at
    OR OLD.expires_at IS NOT NEW.expires_at OR OLD.used_at IS NOT NEW.used_at OR OLD.ended_at IS NOT NEW.ended_at
    OR OLD.created_by_command_id IS NOT NEW.created_by_command_id
BEGIN
    INSERT INTO invites_events (at, label, row_id, context, user_id, created_at, expires_at, used_at, ended_at,
                                created_by_command_id)
    VALUES (unixepoch(), 'update', NEW.id, (SELECT context FROM event_context), NEW.user_id, NEW.created_at,
            NEW.expires_at, NEW.used_at, NEW.ended_at, NEW.created_by_command_id);
END;
CREATE TRIGGER invites_deleted AFTER DELETE ON invites BEGIN
    INSERT INTO invites_events (at, label, row_id, context, user_id, created_at, expires_at, used_at, ended_at,
                                created_by_command_id)
    VALUES (unixepoch(), 'delete', OLD.id, (SELECT context FROM event_context), OLD.user_id, OLD.created_at,
            OLD.expires_at, OLD.used_at, OLD.ended_at, OLD.created_by_command_id);
END;

-- Identities change on every login (when they were last seen); only who they belong to and their name are events.
CREATE TABLE identities_events (
    event_id INTEGER PRIMARY KEY,
    at       INTEGER NOT NULL,
    label    TEXT    NOT NULL CHECK (label IN ('insert', 'update', 'delete')),
    row_id   INTEGER NOT NULL,
    context  TEXT    CHECK (context IS NULL OR json_valid(context)),
    method   TEXT    NOT NULL,
    subject  TEXT    NOT NULL,
    name     TEXT    NOT NULL,
    user_id  INTEGER
) STRICT;
CREATE INDEX identities_events_row ON identities_events (row_id, event_id);

CREATE TRIGGER identities_inserted AFTER INSERT ON identities BEGIN
    INSERT INTO identities_events (at, label, row_id, context, method, subject, name, user_id)
    VALUES (unixepoch(), 'insert', NEW.id, (SELECT context FROM event_context), NEW.method, NEW.subject, NEW.name,
            NEW.user_id);
END;
CREATE TRIGGER identities_updated AFTER UPDATE ON identities
WHEN OLD.method IS NOT NEW.method OR OLD.subject IS NOT NEW.subject OR OLD.name IS NOT NEW.name
    OR OLD.user_id IS NOT NEW.user_id
BEGIN
    INSERT INTO identities_events (at, label, row_id, context, method, subject, name, user_id)
    VALUES (unixepoch(), 'update', NEW.id, (SELECT context FROM event_context), NEW.method, NEW.subject, NEW.name,
            NEW.user_id);
END;
CREATE TRIGGER identities_deleted AFTER DELETE ON identities BEGIN
    INSERT INTO identities_events (at, label, row_id, context, method, subject, name, user_id)
    VALUES (unixepoch(), 'delete', OLD.id, (SELECT context FROM event_context), OLD.method, OLD.subject, OLD.name,
            OLD.user_id);
END;

-- Tokens change on every use; only their denial is an event.
CREATE TABLE tokens_events (
    event_id               INTEGER PRIMARY KEY,
    at                     INTEGER NOT NULL,
    label                  TEXT    NOT NULL CHECK (label IN ('insert', 'update', 'delete')),
    row_id                 TEXT    NOT NULL,
    context                TEXT    CHECK (context IS NULL OR json_valid(context)),
    name                   TEXT,
    revoked_at             INTEGER,
    revoked_by_identity_id INTEGER
) STRICT;
CREATE INDEX tokens_events_row ON tokens_events (row_id, event_id);

CREATE TRIGGER tokens_denied AFTER INSERT ON tokens WHEN NEW.revoked_at IS NOT NULL BEGIN
    INSERT INTO tokens_events (at, label, row_id, context, name, revoked_at, revoked_by_identity_id)
    VALUES (unixepoch(), 'insert', NEW.id, (SELECT context FROM event_context), NEW.name, NEW.revoked_at,
            NEW.revoked_by_identity_id);
END;
CREATE TRIGGER tokens_updated AFTER UPDATE ON tokens
WHEN OLD.revoked_at IS NOT NEW.revoked_at OR OLD.revoked_by_identity_id IS NOT NEW.revoked_by_identity_id
BEGIN
    INSERT INTO tokens_events (at, label, row_id, context, name, revoked_at, revoked_by_identity_id)
    VALUES (unixepoch(), 'update', NEW.id, (SELECT context FROM event_context), NEW.name, NEW.revoked_at,
            NEW.revoked_by_identity_id);
END;
CREATE TRIGGER tokens_deleted AFTER DELETE ON tokens WHEN OLD.revoked_at IS NOT NULL BEGIN
    INSERT INTO tokens_events (at, label, row_id, context, name, revoked_at, revoked_by_identity_id)
    VALUES (unixepoch(), 'delete', OLD.id, (SELECT context FROM event_context), OLD.name, OLD.revoked_at,
            OLD.revoked_by_identity_id);
END;
