-- Hand-mirrored schema, compared against the Flyway migrations by SchemaParityTest.
--
-- The migrations under src/main/resources/db/migration are the production source of truth. This file
-- is their net effect written by hand, and hand mirroring is the likeliest source of a
-- test-versus-production divergence, so the parity test applies the real migrations to one schema and
-- this file to another and compares every column.
--
-- Two deliberate choices:
--
--  * It is NOT named schema.sql and NOT at the classpath root. Spring Boot automatically applies
--    classpath:schema.sql to every embedded datasource, which would silently push this schema into
--    unrelated test contexts.
--  * It is Postgres DDL, and the parity test runs on Postgres, because the migrations themselves are
--    Postgres-only: V5 adds two columns in one ALTER TABLE and indexes LOWER(username), neither of
--    which H2 accepts. A mirror that H2 could run would therefore have to differ from production DDL,
--    which is exactly what a parity test exists to prevent.
--
-- Keep the two in step: when you add a migration, add the same DDL here.
-- V8/V9 created and dropped public_submissions, so it is deliberately absent.

-- V1
CREATE TABLE IF NOT EXISTS directory_entries (
    id UUID PRIMARY KEY,
    phone_digest VARCHAR(64) NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    display_name TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- V4
    phone_masked VARCHAR(32),
    -- V5
    homeserver_id VARCHAR(64),
    username VARCHAR(64),
    -- V6
    discoverable BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_directory_entries_username_lower
    ON directory_entries (LOWER(username));

-- V2
CREATE TABLE IF NOT EXISTS identity_users (
    id UUID PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    pin_hash TEXT,
    pin_set_at TIMESTAMP WITH TIME ZONE,
    pin_reset_requested_at TIMESTAMP WITH TIME ZONE,
    pin_failure_count INTEGER NOT NULL DEFAULT 0,
    pin_locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- V3
    last_pin_change_at TIMESTAMP WITH TIME ZONE,
    -- V10
    last_phone_change_at TIMESTAMP WITH TIME ZONE,
    -- V13
    recovery_completed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    id UUID PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_name TEXT,
    platform TEXT,
    app_version TEXT,
    last_ip TEXT,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_trusted_devices_user_device UNIQUE (user_id, device_id)
);

-- V7
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id UUID PRIMARY KEY,
    user_id TEXT NOT NULL,
    user_handle TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key_cose TEXT NOT NULL,
    signature_count BIGINT NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id
    ON passkey_credentials (user_id);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_handle
    ON passkey_credentials (user_handle);

-- V11
CREATE TABLE IF NOT EXISTS account_genesis (
    account_id         VARCHAR(64) PRIMARY KEY,
    user_id            TEXT UNIQUE,
    origin             VARCHAR(16) NOT NULL,
    state              VARCHAR(16) NOT NULL,
    genesis_version    SMALLINT NOT NULL,
    genesis_suite      SMALLINT NOT NULL,
    genesis_b64        TEXT NOT NULL,
    authority_key_b64  TEXT,
    attach_handle_hash VARCHAR(64),
    expires_at         TIMESTAMP WITH TIME ZONE,
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    attached_at        TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_account_genesis_expires_at
    ON account_genesis (expires_at);

CREATE INDEX IF NOT EXISTS idx_account_genesis_attach_handle
    ON account_genesis (attach_handle_hash);

-- V13
CREATE TABLE IF NOT EXISTS account_authority_record (
    account_id          VARCHAR(64) NOT NULL,
    seq                 BIGINT      NOT NULL,
    magic               VARCHAR(4)  NOT NULL,
    record_b64          TEXT        NOT NULL,
    record_hash         VARCHAR(64) NOT NULL,
    prev_hash           VARCHAR(64) NOT NULL,
    signature_b64       TEXT        NOT NULL,
    authorizing_key_b64 TEXT        NOT NULL,
    state               VARCHAR(16) NOT NULL,
    effective_at        TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    settled_at          TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (account_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_account_authority_record_hash
    ON account_authority_record (record_hash);

CREATE TABLE IF NOT EXISTS account_authority_head (
    account_id           VARCHAR(64) PRIMARY KEY,
    head_hash            VARCHAR(64) NOT NULL,
    head_seq             BIGINT      NOT NULL,
    pending_seq          BIGINT,
    pending_hash         VARCHAR(64),
    pending_magic        VARCHAR(4),
    pending_rank         SMALLINT,
    pending_effective_at TIMESTAMP WITH TIME ZONE,
    cooldown_until       TIMESTAMP WITH TIME ZONE,
    -- V17
    cooldown_magic       VARCHAR(4),
    pending_extended     BOOLEAN     NOT NULL DEFAULT FALSE,
    cancelled_count      INTEGER     NOT NULL DEFAULT 0,
    updated_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS account_authority_device (
    id               UUID        PRIMARY KEY,
    account_id       VARCHAR(64) NOT NULL,
    device_key_b64   TEXT        NOT NULL,
    label            TEXT,
    flags            SMALLINT    NOT NULL DEFAULT 0,
    granted_seq      BIGINT      NOT NULL,
    revoked_seq      BIGINT,
    quarantine_until TIMESTAMP WITH TIME ZONE,
    state            VARCHAR(16) NOT NULL,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_authority_device_key
    ON account_authority_device (account_id, device_key_b64);

CREATE INDEX IF NOT EXISTS idx_account_authority_device_account
    ON account_authority_device (account_id);

CREATE TABLE IF NOT EXISTS account_authority_challenge (
    id             UUID        PRIMARY KEY,
    account_id     VARCHAR(64) NOT NULL,
    session_hash   VARCHAR(64) NOT NULL,
    purpose        VARCHAR(16) NOT NULL,
    challenge_hash VARCHAR(64) NOT NULL UNIQUE,
    factor         VARCHAR(16) NOT NULL,
    factor_created_at TIMESTAMP WITH TIME ZONE,
    expires_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    spent_at       TIMESTAMP WITH TIME ZONE,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_account_authority_challenge_expires
    ON account_authority_challenge (expires_at);

CREATE INDEX IF NOT EXISTS idx_account_authority_challenge_account
    ON account_authority_challenge (account_id);

-- V14
CREATE TABLE IF NOT EXISTS security_notification_device (
    id                      UUID        PRIMARY KEY,
    user_id                 TEXT        NOT NULL,
    installation_id         TEXT        NOT NULL,
    platform                TEXT        NOT NULL,
    app_id                  TEXT        NOT NULL,
    token                   TEXT        NOT NULL,
    token_fingerprint       TEXT        NOT NULL,
    device_label            TEXT,
    authority_device_key_b64 TEXT,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    consecutive_failures    INT         NOT NULL DEFAULT 0,
    last_failure_at         TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_security_notification_device_install
    ON security_notification_device (user_id, installation_id);

CREATE INDEX IF NOT EXISTS idx_security_notification_device_user
    ON security_notification_device (user_id);

-- V14 (continued): a challenge minted for a purpose with no factor has none to record.
ALTER TABLE account_authority_challenge
    ALTER COLUMN factor DROP NOT NULL;

-- V15
CREATE TABLE IF NOT EXISTS account_authority_candidate (
    id             UUID        PRIMARY KEY,
    account_id     VARCHAR(64) NOT NULL,
    device_key_b64 TEXT        NOT NULL,
    fingerprint    VARCHAR(16) NOT NULL,
    label          TEXT,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    expires_at     TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_authority_candidate_key
    ON account_authority_candidate (account_id, device_key_b64);

CREATE INDEX IF NOT EXISTS idx_account_authority_candidate_account
    ON account_authority_candidate (account_id);

CREATE INDEX IF NOT EXISTS idx_account_authority_candidate_expires
    ON account_authority_candidate (expires_at);

-- V16
CREATE TABLE IF NOT EXISTS account_authority_web_step_up (
    id                UUID        PRIMARY KEY,
    user_id           TEXT        NOT NULL,
    session_hash      VARCHAR(64) NOT NULL,
    purpose           VARCHAR(16) NOT NULL,
    factor            VARCHAR(16) NOT NULL,
    factor_created_at TIMESTAMP WITH TIME ZONE,
    expires_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at       TIMESTAMP WITH TIME ZONE,
    created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_account_authority_web_step_up_lookup
    ON account_authority_web_step_up (user_id, purpose);

CREATE INDEX IF NOT EXISTS idx_account_authority_web_step_up_expires
    ON account_authority_web_step_up (expires_at);

-- V18
CREATE TABLE IF NOT EXISTS account_authority_publication (
    account_id     VARCHAR(64) NOT NULL PRIMARY KEY,
    head_seq       BIGINT      NOT NULL,
    head_hash      VARCHAR(64) NOT NULL,
    homeserver_id  VARCHAR(64) NOT NULL,
    record_b64     TEXT        NOT NULL,
    signature_b64  TEXT        NOT NULL,
    payload_hash   VARCHAR(64) NOT NULL,
    issued_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after      TIMESTAMP WITH TIME ZONE NOT NULL,
    signed_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    confirmed_at   TIMESTAMP WITH TIME ZONE,
    attempts       INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_account_authority_publication_unconfirmed
    ON account_authority_publication (confirmed_at);
