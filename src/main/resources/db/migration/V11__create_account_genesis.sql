-- ADM-008 Phase 3: one genesis row per account, so every account has a permanent accountId.
--
-- Additive and nullable, in the idempotent style of V4-V10. Nothing in this phase reads these rows for
-- routing or for login; they exist so an accountId can be derived, stored and audited. A GENESIS row is
-- registered by the client at POST /account/genesis and attached to an account at signup; a BOOTSTRAP
-- row is minted by the service for accounts that predate account authority or were created on the web
-- (ADM-001 L5 path B1), and is told apart from a rooted account by origin = 'BOOTSTRAP', a NULL
-- authority key, and the root class byte 0x00 inside the accountId itself.
--
-- TEXT rather than BYTEA and no partial index, so the H2 PostgreSQL-mode test schema and a real
-- Postgres behave alike.
--
-- Rollback: DROP TABLE account_genesis plus its flyway_schema_history row. Nothing reads it, so the
-- flags alone (identity.genesis.*) are enough to make the feature inert without dropping anything.
CREATE TABLE IF NOT EXISTS account_genesis (
    -- The 58-character accountId. Permanent: kept even when the account is deactivated (ADM-001 L3).
    account_id         VARCHAR(64) PRIMARY KEY,
    -- The MXID once attached; NULL while a registered genesis is still PENDING. UNIQUE so one account
    -- can never hold two genesis rows, which is also what makes two racing attaches resolve to one.
    user_id            TEXT UNIQUE,
    -- GENESIS | BOOTSTRAP. The audit marker ADM-001 L5 requires; no code path in this phase updates it.
    origin             VARCHAR(16) NOT NULL,
    -- PENDING | ATTACHED.
    state              VARCHAR(16) NOT NULL,
    genesis_version    SMALLINT NOT NULL,
    genesis_suite      SMALLINT NOT NULL,
    -- The exact canonical bytes as received, base64url. The accountId is the hash of these bytes, so
    -- storing them verbatim is what keeps the id re-derivable and auditable.
    genesis_b64        TEXT NOT NULL,
    -- Raw 32-byte Ed25519 authority key, base64url. NULL for BOOTSTRAP, which commits no key.
    authority_key_b64  TEXT,
    -- SHA-256 hex of the single-use attach handle. The handle itself is never stored.
    attach_handle_hash VARCHAR(64),
    -- When a PENDING registration stops being attachable.
    expires_at         TIMESTAMP WITH TIME ZONE,
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    attached_at        TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_account_genesis_expires_at
    ON account_genesis (expires_at);

CREATE INDEX IF NOT EXISTS idx_account_genesis_attach_handle
    ON account_genesis (attach_handle_hash);
