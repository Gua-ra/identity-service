-- ADM-009 decision 12: what this deployment has published about each account's settled chain head.
--
-- Decision 12 reserves an ACCOUNT_AUTHORITY log leaf for the chain head and states that until it is
-- written, a class 0x00 account's chain is an assertion by the homeserver that stores it. This table is
-- the publishing side of that leaf: one row per account, holding the signed head object exactly as it
-- was sent and the payload hash the leaf commits.
--
-- Additive and idempotent, in the style of V13-V17. Nothing here is read while
-- identity.authority.publication.enabled is false: with that flag off no head is signed, no resolver is
-- contacted and no row is ever written, and the chain behaves exactly as it does with the flag on but
-- unpublished. The switch is separate from identity.authority.enabled on purpose, so the chain can run
-- while nothing reaches federation state.
--
-- Rollback: turn identity.authority.publication.enabled off. The table may then be dropped
-- (DROP TABLE account_authority_publication plus its flyway_schema_history row), but it does not need
-- to be: nothing else reads it. Keeping it is the better choice, because the row is what makes a
-- republish idempotent, and dropping it would make the next publication re-sign bytes the log already
-- carries.
--
-- TEXT rather than BYTEA and no expression indexes, so the H2 PostgreSQL-mode test schema and a real
-- Postgres behave alike: the choice V11 and V13 made, for the same reason.

CREATE TABLE IF NOT EXISTS account_authority_publication (
    -- The same opaque 58-character account reference every other authority table is keyed on. One row
    -- per account: a published head replaces its predecessor rather than accumulating, because the
    -- history is in the log and this row is only a record of what was last sent.
    account_id     VARCHAR(64) NOT NULL PRIMARY KEY,
    -- The position and hash this row published. Replaced only when the settled head moves forward, so a
    -- cancellation that rolled the chain head back can never make this row go backwards.
    head_seq       BIGINT      NOT NULL,
    head_hash      VARCHAR(64) NOT NULL,
    -- The federation roster id the head was signed under, never the Matrix domain.
    homeserver_id  VARCHAR(64) NOT NULL,
    -- The canonical bytes as signed, base64url, and the detached signature, base64. Stored verbatim and
    -- never re-encoded: a retry resends exactly these bytes, which is what makes a republish commit the
    -- same leaf instead of a second one.
    record_b64     TEXT        NOT NULL,
    signature_b64  TEXT        NOT NULL,
    -- SHA-256 hex over those canonical bytes: exactly the payload the ACCOUNT_AUTHORITY leaf commits.
    -- Held so that "has this head already been published" is answerable without decoding anything.
    payload_hash   VARCHAR(64) NOT NULL,
    issued_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after      TIMESTAMP WITH TIME ZONE NOT NULL,
    signed_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- When the resolver accepted it. NULL means signed but not yet acknowledged, which the next pass over
    -- this account retries with the stored bytes rather than with a new signature.
    confirmed_at   TIMESTAMP WITH TIME ZONE,
    -- How many delivery attempts this row has had. Read by nothing that decides anything; it exists so a
    -- resolver that has been unreachable for a week is visible as that rather than as an absence.
    attempts       INTEGER     NOT NULL DEFAULT 0
);

-- Answers "which accounts are signed but unacknowledged" without a full scan.
CREATE INDEX IF NOT EXISTS idx_account_authority_publication_unconfirmed
    ON account_authority_publication (confirmed_at);
