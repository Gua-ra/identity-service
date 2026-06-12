-- Routing-at-scale: record which homeserver an account lives on, and reserve a
-- globally-unique (within the Gua federation) username that acts as a stable
-- alias decoupled from the Matrix user id.
--
-- Both columns are nullable so existing rows (provisioned before routing) keep
-- working; new sign-ups populate them. The username uniqueness is enforced
-- case-insensitively via a functional unique index (Postgres allows multiple
-- NULLs, so legacy rows without a username do not collide).
ALTER TABLE directory_entries
    ADD COLUMN IF NOT EXISTS homeserver_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS username      VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS ux_directory_entries_username_lower
    ON directory_entries (LOWER(username));
