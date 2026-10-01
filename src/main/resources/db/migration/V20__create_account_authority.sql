-- Account authority chain: records, head, devices and challenges.

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

-- Lets a transition refuse a PIN minted by a recent recovery.
ALTER TABLE identity_users
    ADD COLUMN IF NOT EXISTS recovery_completed_at TIMESTAMP WITH TIME ZONE;
