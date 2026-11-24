-- Version 3: when each signed token was minted, and tokens registered before they're used.
--
-- A token's row now also comes from `tokens new` registering it, so first_used_at stays NULL until it logs in. A row
-- whose id starts `name:` denies every token for that name minted before its revoked_at; it never expires.

ALTER TABLE tokens ADD COLUMN issued_at INTEGER;
