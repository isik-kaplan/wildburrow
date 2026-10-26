-- What the server records, version 1. Times are unix seconds, durations milliseconds. Nothing secret is stored: no lock
-- secret, password, token, link key, hand-off code or verifier, only digests of them, and paths have link keys and
-- codes cut out. Every id is assigned by the server, so writes can wait for the next batch.

-- ---------------------------------------------------------------------------------------------------------------------
-- The server

-- One run of `wildburrow serve`, from start to stop.
CREATE TABLE runs (
    id          INTEGER PRIMARY KEY,
    version     TEXT    NOT NULL,
    hostname    TEXT    NOT NULL,
    domain      TEXT    NOT NULL,
    -- The settings it ran with, secrets shown only as set.
    settings    TEXT    NOT NULL CHECK (json_valid(settings)),
    started_at  INTEGER NOT NULL,
    stopped_at  INTEGER,
    CHECK (stopped_at IS NULL OR stopped_at >= started_at)
) STRICT;

-- The server's own log lines, INFO and up.
CREATE TABLE logs (
    id      INTEGER PRIMARY KEY,
    run_id  INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    at      INTEGER NOT NULL,
    level   TEXT    NOT NULL CHECK (level IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    logger  TEXT    NOT NULL,
    message TEXT    NOT NULL
) STRICT;
CREATE INDEX logs_at ON logs (at);
CREATE INDEX logs_run ON logs (run_id, at);

-- ---------------------------------------------------------------------------------------------------------------------
-- Who connects

-- Who logged in, by method and subject: a key's fingerprint, a token's id or digest, or the name given with a password.
CREATE TABLE identities (
    id            INTEGER PRIMARY KEY,
    method        TEXT    NOT NULL,
    subject       TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    UNIQUE (method, subject),
    CHECK (last_seen_at >= first_seen_at)
) STRICT;
CREATE INDEX identities_name ON identities (name);

-- Every signed token the server has seen used or been told to deny.
CREATE TABLE tokens (
    id                     TEXT    PRIMARY KEY,
    identity_id            INTEGER REFERENCES identities (id) ON DELETE SET NULL,
    name                   TEXT,
    -- The names it may claim, NULL for any.
    names                  TEXT    CHECK (names IS NULL OR json_valid(names)),
    expires_at             INTEGER,
    first_used_at          INTEGER,
    last_used_at           INTEGER,
    revoked_at             INTEGER,
    revoked_by_identity_id INTEGER REFERENCES identities (id) ON DELETE SET NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX tokens_identity ON tokens (identity_id);
CREATE INDEX tokens_revoked_by ON tokens (revoked_by_identity_id);

-- Every try at logging in to the server, over either transport.
CREATE TABLE auth_attempts (
    id          INTEGER PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    at          INTEGER NOT NULL,
    transport   TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    address     TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    ok          INTEGER NOT NULL CHECK (ok IN (0, 1)),
    identity_id INTEGER REFERENCES identities (id) ON DELETE SET NULL,
    -- Why it didn't get in.
    reason      TEXT,
    CHECK (ok = 0 OR identity_id IS NOT NULL),
    CHECK (ok = 1 OR reason IS NOT NULL)
) STRICT;
CREATE INDEX auth_attempts_at ON auth_attempts (at);
CREATE INDEX auth_attempts_failures ON auth_attempts (address, at) WHERE ok = 0;
CREATE INDEX auth_attempts_identity ON auth_attempts (identity_id, at);
CREATE INDEX auth_attempts_run ON auth_attempts (run_id);

-- One logged-in connection: what `tunnels` lists and `kick` ends.
CREATE TABLE sessions (
    id                  TEXT    PRIMARY KEY,
    run_id              INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    identity_id         INTEGER NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    token_id            TEXT    REFERENCES tokens (id) ON DELETE SET NULL,
    transport           TEXT    NOT NULL,
    admin               INTEGER NOT NULL CHECK (admin IN (0, 1)),
    address             TEXT    NOT NULL,
    port                INTEGER NOT NULL,
    -- Sent in the hello from 0.5.0; NULL for ssh and older clients.
    client_version      TEXT,
    client_platform     TEXT,
    expires_at          INTEGER,
    started_at          INTEGER NOT NULL,
    ended_at            INTEGER,
    end_reason          TEXT,
    -- The `kick` that ended it, and through it who kicked.
    ended_by_command_id INTEGER REFERENCES commands (id) ON DELETE SET NULL,
    CHECK (ended_at IS NULL OR ended_at >= started_at)
) STRICT, WITHOUT ROWID;
CREATE INDEX sessions_identity ON sessions (identity_id, started_at);
CREATE INDEX sessions_live ON sessions (identity_id) WHERE ended_at IS NULL;
CREATE INDEX sessions_run ON sessions (run_id);
CREATE INDEX sessions_token ON sessions (token_id);
CREATE INDEX sessions_ended_by ON sessions (ended_by_command_id);

-- What a session asked the server for besides tunnels.
CREATE TABLE commands (
    id         INTEGER PRIMARY KEY,
    session_id TEXT    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    at         INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    -- As sent and as answered, with link URLs cut down to their tunnel; recorded before it's answered, so what
    -- answering it does can point at it.
    request    TEXT    NOT NULL CHECK (json_valid(request)),
    answer     TEXT             CHECK (json_valid(answer))
) STRICT;
CREATE INDEX commands_session ON commands (session_id, at);
CREATE INDEX commands_kind ON commands (kind, at);

-- ---------------------------------------------------------------------------------------------------------------------
-- Tunnels

-- One bind: the names a session asked for in one go, and the lock they came with.
CREATE TABLE tunnels (
    id          INTEGER PRIMARY KEY,
    session_id  TEXT    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    lock_id     TEXT    REFERENCES locks (id) ON DELETE SET NULL,
    -- Whether search engines may index it.
    indexed     INTEGER NOT NULL CHECK (indexed IN (0, 1)),
    opened_at   INTEGER NOT NULL,
    closed_at   INTEGER,
    -- Why it was refused, all its names with it; NULL for one bound.
    rejected    TEXT,
    CHECK (closed_at IS NULL OR closed_at >= opened_at),
    CHECK (rejected IS NULL OR closed_at = opened_at)
) STRICT;
CREATE INDEX tunnels_session ON tunnels (session_id);
CREATE INDEX tunnels_lock ON tunnels (lock_id);
CREATE INDEX tunnels_live ON tunnels (session_id) WHERE closed_at IS NULL;

-- Each name a bind asked for, foo or *.foo, and the URL it got.
CREATE TABLE tunnel_names (
    tunnel_id INTEGER NOT NULL REFERENCES tunnels (id) ON DELETE CASCADE,
    name      TEXT    NOT NULL,
    url       TEXT,
    PRIMARY KEY (tunnel_id, name)
) STRICT, WITHOUT ROWID;
CREATE INDEX tunnel_names_name ON tunnel_names (name);

-- ---------------------------------------------------------------------------------------------------------------------
-- Locks: who may get in, and who did

-- A lock outlives the connections that carry it. Its id is HMAC(secret, "id"); the secret itself is never stored, so a
-- copy of this file can't forge a cookie.
CREATE TABLE locks (
    id          TEXT    PRIMARY KEY,
    identity_id INTEGER NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    home        TEXT    NOT NULL,
    on_domain   INTEGER NOT NULL CHECK (on_domain IN (0, 1)),
    settings    TEXT    NOT NULL CHECK (json_valid(settings)),
    created_at  INTEGER NOT NULL,
    -- When the last tunnel carrying it closed; a reconnect brings it back.
    ended_at    INTEGER
) STRICT, WITHOUT ROWID;
CREATE INDEX locks_identity ON locks (identity_id);

-- How a name gets in: a password, or a link. A password and a link may share a name.
CREATE TABLE credentials (
    -- The lock's id, then the credential's kind and label: the same on every reconnect.
    id                    TEXT    PRIMARY KEY,
    lock_id               TEXT    NOT NULL REFERENCES locks (id) ON DELETE CASCADE,
    kind                  TEXT    NOT NULL CHECK (kind IN ('password', 'link')),
    -- The name the app sees in X-Wildburrow-User.
    label                 TEXT    NOT NULL,
    -- sha256 of the key only the link's URL carries.
    link_digest           TEXT    CHECK (link_digest IS NULL OR length(link_digest) = 64),
    link_host             TEXT,
    link_path             TEXT,
    -- NULL for any number of uses.
    max_uses              INTEGER CHECK (max_uses IS NULL OR max_uses > 0),
    uses                  INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    last_used_at          INTEGER,
    logins                INTEGER NOT NULL DEFAULT 0 CHECK (logins >= 0),
    last_seen_at          INTEGER,
    expires_at            INTEGER,
    -- The `links add` that made it, NULL for one made with the lock.
    created_by_command_id INTEGER REFERENCES commands (id) ON DELETE SET NULL,
    created_at            INTEGER NOT NULL,
    ended_at              INTEGER,
    CHECK ((kind = 'link') = (link_digest IS NOT NULL))
) STRICT, WITHOUT ROWID;
CREATE INDEX credentials_lock ON credentials (lock_id);
CREATE INDEX credentials_command ON credentials (created_by_command_id);

-- Every time a link's page is opened, so a chat app's preview shows apart from the click.
CREATE TABLE link_opens (
    id            INTEGER PRIMARY KEY,
    credential_id TEXT    NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    at            INTEGER NOT NULL,
    address       TEXT    NOT NULL,
    user_agent    TEXT,
    outcome       TEXT    NOT NULL CHECK (outcome IN ('shown', 'used'))
) STRICT;
CREATE INDEX link_opens_credential ON link_opens (credential_id, at);

-- Every try at a lock: the form, the header, or a link.
CREATE TABLE login_attempts (
    id            INTEGER PRIMARY KEY,
    lock_id       TEXT    NOT NULL REFERENCES locks (id) ON DELETE CASCADE,
    at            INTEGER NOT NULL,
    via           TEXT    NOT NULL CHECK (via IN ('form', 'header', 'link')),
    -- The username typed, matching one or not.
    label         TEXT,
    credential_id TEXT    REFERENCES credentials (id) ON DELETE SET NULL,
    address       TEXT    NOT NULL,
    user_agent    TEXT,
    ok            INTEGER NOT NULL CHECK (ok IN (0, 1)),
    reason        TEXT    CHECK (reason IN ('wrong-password', 'limited', 'spent')),
    CHECK ((ok = 1) = (reason IS NULL)),
    CHECK (ok = 0 OR credential_id IS NOT NULL)
) STRICT;
CREATE INDEX login_attempts_failures ON login_attempts (lock_id, at) WHERE ok = 0;
CREATE INDEX login_attempts_address ON login_attempts (address, at) WHERE ok = 0;
CREATE INDEX login_attempts_credential ON login_attempts (credential_id);

-- Codes that carry a login from the lock's home to another host of its tunnel, kept after use.
CREATE TABLE handoff_codes (
    digest        TEXT    PRIMARY KEY CHECK (length(digest) = 64),
    credential_id TEXT    NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    host          TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    redeemed_at   INTEGER,
    CHECK (redeemed_at IS NULL OR redeemed_at >= created_at)
) STRICT, WITHOUT ROWID;
CREATE INDEX handoff_codes_credential ON handoff_codes (credential_id);

-- ---------------------------------------------------------------------------------------------------------------------
-- Visitors

-- One connection to the edge.
CREATE TABLE connections (
    id          INTEGER PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    at          INTEGER NOT NULL,
    duration_ms INTEGER CHECK (duration_ms >= 0),
    scheme      TEXT    NOT NULL CHECK (scheme IN ('http', 'https')),
    -- The visitor, and the proxy that told us so when PROXY protocol is on.
    address     TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    via_proxy   TEXT,
    tunnel_id   INTEGER REFERENCES tunnels (id) ON DELETE SET NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out   INTEGER NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    -- With traffic kept: whether WILDBURROW_DATABASE_TRAFFIC_MAX cut it short.
    truncated   INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1))
) STRICT;
CREATE INDEX connections_at ON connections (at);
CREATE INDEX connections_address ON connections (address, at);
CREATE INDEX connections_tunnel ON connections (tunnel_id);
CREATE INDEX connections_run ON connections (run_id);

-- Each request on a connection, and what answered it.
CREATE TABLE requests (
    id            INTEGER PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES connections (id) ON DELETE CASCADE,
    at            INTEGER NOT NULL,
    method        TEXT    NOT NULL,
    host          TEXT    NOT NULL,
    path          TEXT    NOT NULL,
    query         TEXT,
    user_agent    TEXT,
    referer       TEXT,
    lock_id       TEXT    REFERENCES locks (id) ON DELETE SET NULL,
    -- Who it went through as, by cookie or by header.
    credential_id TEXT    REFERENCES credentials (id) ON DELETE SET NULL,
    -- Ours, or the app's from its status line.
    status        INTEGER CHECK (status BETWEEN 100 AND 599)
) STRICT;
CREATE INDEX requests_connection ON requests (connection_id);
CREATE INDEX requests_at ON requests (at);
CREATE INDEX requests_host ON requests (host, at);
CREATE INDEX requests_lock ON requests (lock_id);
CREATE INDEX requests_credential ON requests (credential_id);

-- Only with WILDBURROW_DATABASE_RECORD=everything: the bytes themselves, as the app sent and received them, in the order
-- they crossed.
CREATE TABLE traffic (
    connection_id INTEGER NOT NULL REFERENCES connections (id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL CHECK (seq >= 0),
    -- 'in' from the visitor to the app, 'out' back.
    direction     TEXT    NOT NULL CHECK (direction IN ('in', 'out')),
    -- Since the connection opened.
    at_ms         INTEGER NOT NULL CHECK (at_ms >= 0),
    -- zlib when that came out smaller, as text and JSON do; images and video stay raw.
    encoding      TEXT    NOT NULL CHECK (encoding IN ('raw', 'zlib')),
    size          INTEGER NOT NULL CHECK (size > 0),
    data          BLOB    NOT NULL,
    PRIMARY KEY (connection_id, seq)
) STRICT;

-- ---------------------------------------------------------------------------------------------------------------------
-- Certificates and DNS

-- Every certificate asked for, and what came back; the keys stay in the cert store.
CREATE TABLE certificates (
    id           INTEGER PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    parent       TEXT    NOT NULL,
    requested_at INTEGER NOT NULL,
    finished_at  INTEGER,
    ok           INTEGER CHECK (ok IN (0, 1)),
    error        TEXT,
    CHECK ((finished_at IS NULL) = (ok IS NULL))
) STRICT;
CREATE INDEX certificates_parent ON certificates (parent, requested_at);
CREATE INDEX certificates_run ON certificates (run_id);

-- Records the server set: CNAMEs for new parents, and ACME's TXT challenges.
CREATE TABLE dns_changes (
    id     INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    at     INTEGER NOT NULL,
    action TEXT    NOT NULL,
    record TEXT    NOT NULL,
    value  TEXT,
    ok     INTEGER NOT NULL CHECK (ok IN (0, 1)),
    error  TEXT,
    CHECK (ok = 1 OR error IS NOT NULL)
) STRICT;
CREATE INDEX dns_changes_record ON dns_changes (record, at);
CREATE INDEX dns_changes_run ON dns_changes (run_id);
