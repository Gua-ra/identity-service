-- ADM-009 decision 5, revision 4: how a new device's public key reaches the device that signs the grant.
--
-- Additive and idempotent, in the style of V4-V14, and inert while identity.authority.enabled is false.
--
-- Revisions 1 to 3 fixed both ends of the transfer and left the middle undefined: the new device
-- generates its own key and never receives another device's, an existing active device signs a
-- DeviceGrant over it, and nothing said how the public key crosses between them. This table is that
-- middle. The new device posts only its public key under its own authenticated session, the server
-- hands back a short human fingerprint, and the granting device reads the account's candidates, shows
-- the fingerprint and signs over the one the user confirms.
--
-- The fingerprint is the only thing crossing between the two devices that a human has to compare, so it
-- is derived from the key itself rather than stored as a separate secret: both devices compute the same
-- eight characters from the same 32 bytes, and a mismatch means they are not looking at the same key.
--
-- Rollback: turn identity.authority.* off. The table may then be dropped
-- (DROP TABLE account_authority_candidate plus its flyway_schema_history row).

CREATE TABLE IF NOT EXISTS account_authority_candidate (
    id             UUID        PRIMARY KEY,
    -- The account whose chain a grant over this key would join.
    account_id     VARCHAR(64) NOT NULL,
    -- Raw 32-byte Ed25519 device authority key, base64url. The public half only: a candidate hands over
    -- nothing a holder of this row could sign with.
    device_key_b64 TEXT        NOT NULL,
    -- Eight characters of an alphabet with no look-alikes, derived from the key. Stored so a listing does
    -- not have to recompute it, and never used to look a candidate up.
    fingerprint    VARCHAR(16) NOT NULL,
    -- The label the new device suggests for itself, at most the 16 bytes a record may carry.
    label          TEXT,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- Short. A candidate is a step in a ceremony two people are performing right now, and one left lying
    -- around is a key a grant could later be signed over without anybody comparing anything.
    expires_at     TIMESTAMP WITH TIME ZONE NOT NULL
);

-- One row per key per account, so registering twice refreshes rather than accumulates, and so a grant
-- naming a key finds exactly one candidate or none.
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_authority_candidate_key
    ON account_authority_candidate (account_id, device_key_b64);

CREATE INDEX IF NOT EXISTS idx_account_authority_candidate_account
    ON account_authority_candidate (account_id);

CREATE INDEX IF NOT EXISTS idx_account_authority_candidate_expires
    ON account_authority_candidate (expires_at);
