-- ADM-009: the account authority chain, the device set, and the state the windows run on.
--
-- Additive and idempotent, in the style of V4-V12. Nothing here is read while
-- identity.authority.enabled is false: with the flag off no row is ever written, every authority
-- endpoint answers 503, and this deployment behaves exactly as it did before the feature existed.
--
-- The chain is the authority (ADM-009 decision 2). There is no ambient "the account's key" outside
-- it, and account_genesis is left exactly as it is: adoption does not change the accountId, the
-- genesis row or its origin (decision 1), so nothing in this migration touches that table.
--
-- TEXT rather than BYTEA, no partial indexes and no expression indexes, so the H2 PostgreSQL-mode
-- test schema and a real Postgres behave alike, the same choice V11 made and for the same reason.
--
-- Rollback: turn identity.authority.* off. The tables may then be dropped
-- (DROP TABLE account_authority_challenge, account_authority_device, account_authority_record,
-- account_authority_head plus their flyway_schema_history row), but they do not need to be:
-- nothing else reads them, so the flag alone makes the feature inert. identity_users.
-- recovery_completed_at is kept either way, because it is a fact about the account rather than
-- feature state, and a dropped stamp would silently reopen the hold of decision 9 rule 3.

-- One row per accepted record, append-only. The canonical bytes are stored exactly as received,
-- base64url, because the record hash and every signature cover those bytes and the server never
-- re-encodes what it is about to hash (ADM-008 decision 1, carried forward by ADM-009 decision 2).
CREATE TABLE IF NOT EXISTS account_authority_record (
    -- The 58-character accountId of the account whose chain this record belongs to.
    account_id          VARCHAR(64) NOT NULL,
    -- 1 in the first record and exactly one more than the previous. Part of the primary key, so
    -- two records can never share a position: that is half of the compare-and-set of decision 3.
    seq                 BIGINT      NOT NULL,
    -- GUAA | GUAD | GUAX | GUAR. The record type, and the signature domain.
    magic               VARCHAR(4)  NOT NULL,
    record_b64          TEXT        NOT NULL,
    -- SHA-256 hex over the canonical bytes. What the next record's prev_hash must equal.
    record_hash         VARCHAR(64) NOT NULL,
    -- 64 zeros in the first record of a chain.
    prev_hash           VARCHAR(64) NOT NULL,
    -- Detached, never part of the hashed bytes.
    signature_b64       TEXT        NOT NULL,
    -- The key whose signature authorized this record, base64url raw Ed25519. Inside the hashed
    -- bytes for every type that carries the field; for AdoptRoot and for the account-recovery
    -- authorization it is the record's own device key, which is what actually signed.
    authorizing_key_b64 TEXT        NOT NULL,
    -- PENDING | ACTIVE | CANCELLED | EXPIRED. A PENDING record already holds its seq
    -- (decision 3), so an opposable transition cannot be starved by an immediate one.
    state               VARCHAR(16) NOT NULL,
    -- When the opposition window ends. NULL for a record that took effect on acceptance.
    effective_at        TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- When it left PENDING, whichever way it left.
    settled_at          TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (account_id, seq)
);

-- Opposition names a record by its hash, so that lookup is indexed rather than a chain scan.
CREATE INDEX IF NOT EXISTS idx_account_authority_record_hash
    ON account_authority_record (record_hash);

-- Exactly one head per account (ADM-009 decision 3). Every write locks this row FOR UPDATE, which
-- is where the compare-and-set lives: two devices acting at once produce one winner and one
-- refusal carrying the current head, never a merge and never two chains.
CREATE TABLE IF NOT EXISTS account_authority_head (
    account_id           VARCHAR(64) PRIMARY KEY,
    -- SHA-256 hex of the last accepted record; 64 zeros while the chain is empty.
    head_hash            VARCHAR(64) NOT NULL,
    -- 0 while the chain is empty.
    head_seq             BIGINT      NOT NULL,
    -- The slot a record inside its opposition window has already taken. NULL when none is pending.
    pending_seq          BIGINT,
    pending_hash         VARCHAR(64),
    pending_magic        VARCHAR(4),
    -- The rank of decision 3's table: 2 recovery-key recovery, 1 device-signed, 0 account-recovery
    -- recovery. Stored so the rank comparison does not have to re-decode the pending record.
    pending_rank         SMALLINT,
    pending_effective_at TIMESTAMP WITH TIME ZONE,
    -- When another transition of the same shape may be opened. One window, per decision 4's bounds.
    cooldown_until       TIMESTAMP WITH TIME ZONE,
    updated_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- The device set the chain leaves active (ADM-009 decision 5). A per-device key, never one key
-- copied to every device: copying makes revocation meaningless, because the revoked device still
-- holds the key the account is defined by.
CREATE TABLE IF NOT EXISTS account_authority_device (
    id               UUID        PRIMARY KEY,
    account_id       VARCHAR(64) NOT NULL,
    -- Raw 32-byte Ed25519 device authority key, base64url.
    device_key_b64   TEXT        NOT NULL,
    -- The 16 label bytes as the record carried them, UTF-8 with the zero padding trimmed. What a
    -- notification is allowed to name, and nothing else.
    label            TEXT,
    flags            SMALLINT    NOT NULL DEFAULT 0,
    granted_seq      BIGINT      NOT NULL,
    revoked_seq      BIGINT,
    -- While this is in the future the device is quarantined: it may not sign a grant, a revocation
    -- or an approval, and it does not count toward the active device a revocation must leave behind.
    quarantine_until TIMESTAMP WITH TIME ZONE,
    -- ACTIVE | QUARANTINED | REVOKED.
    state            VARCHAR(16) NOT NULL,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- One row per key per account. A device key is named by a grant and by a revocation, so the pair
-- has to be unique or a revocation could not say which row it settles.
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_authority_device_key
    ON account_authority_device (account_id, device_key_b64);

CREATE INDEX IF NOT EXISTS idx_account_authority_device_account
    ON account_authority_device (account_id);

-- The server challenge every record signs (ADM-009 decision 2, "one preimage rule, for every
-- type"). Only the SHA-256 of the challenge is stored, the way account_genesis stores only the
-- hash of an attach handle: a dump of this table hands nobody a challenge to sign.
CREATE TABLE IF NOT EXISTS account_authority_challenge (
    id             UUID        PRIMARY KEY,
    account_id     VARCHAR(64) NOT NULL,
    -- SHA-256 hex of the bearer token the challenge was minted for. A challenge is held against
    -- the account AND the acting stepped-up session, so it is not transferable to another session.
    session_hash   VARCHAR(64) NOT NULL,
    -- ADOPT | GRANT | REVOKE | RECOVER | APPROVE. The step-up is scoped to this, so a step-up
    -- performed for a phone change or a PIN change does not carry over (decision 4 step 2).
    purpose        VARCHAR(16) NOT NULL,
    challenge_hash VARCHAR(64) NOT NULL UNIQUE,
    -- Which factor settled the step-up that minted it, and when that factor came into being, so
    -- the fresh-factor hold is weighed on the credential actually presented.
    factor         VARCHAR(16) NOT NULL,
    factor_created_at TIMESTAMP WITH TIME ZONE,
    expires_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    -- Burned on acceptance AND on refusal, so a captured request body is useless.
    spent_at       TIMESTAMP WITH TIME ZONE,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_account_authority_challenge_expires
    ON account_authority_challenge (expires_at);

CREATE INDEX IF NOT EXISTS idx_account_authority_challenge_account
    ON account_authority_challenge (account_id);

-- When an account recovery last completed (ADM-009 decision 9 rule 3, gate 4).
--
-- The rule that carries the weight is stated on the account rather than on the session, and the
-- account had nowhere to hold it: pin_reset_requested_at is cleared on completion, and pin_set_at
-- cannot tell a recovery from an ordinary PIN change. Without this stamp the shipped recovery path
-- mints an attacker-chosen PIN and an authority transition accepts it days later as proof of
-- possession. Nothing existing reads it.
ALTER TABLE identity_users
    ADD COLUMN IF NOT EXISTS recovery_completed_at TIMESTAMP WITH TIME ZONE;
