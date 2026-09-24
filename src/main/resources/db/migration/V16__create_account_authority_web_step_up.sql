-- ADM-009 decision 4 step 2: the step-up a platform with no WebAuthn ceremony of its own can still take.
--
-- Additive and idempotent, in the style of V4-V15, and inert while identity.authority.enabled is false:
-- the endpoint that mints a sheet answers 503, no row is ever written, and the challenge endpoint reads
-- this table only for a purpose the chain is switched on for.
--
-- Why a table rather than a claim in a request. The policy is a user-verifying passkey assertion, or the
-- PIN where policy allows it, and never a code sent to the number. One client cannot run the assertion
-- natively at all, so on that platform the policy would collapse to PIN-only and an account that
-- correctly chose passkey-only at signup would be told to add a PIN to gain authority. The ceremony
-- therefore runs in the web sheet the factor-enrollment handoff already uses, and what the sheet leaves
-- behind is this row: a proof the server itself observed, bound to the account and to the access token
-- that asked for the sheet, scoped to one purpose, with the challenge's own 15 minute life, consumed
-- exactly once by POST /account/authority/challenge.
--
-- What is deliberately absent: any column a client could set to say which factor it produced, and any
-- shape in which a phone code could be recorded. The factor column is written by the server from the
-- ceremony it just ran, and the only two values it may hold are the passkey and the PIN.
--
-- Rollback: turn identity.authority.* off. The table may then be dropped
-- (DROP TABLE account_authority_web_step_up plus its flyway_schema_history row).

CREATE TABLE IF NOT EXISTS account_authority_web_step_up (
    id                UUID        PRIMARY KEY,
    -- The account holder who proved a factor in the sheet. Keyed on the subject rather than on an
    -- accountId: what this row records is a factor of an account, which needs no account object.
    user_id           TEXT        NOT NULL,
    -- SHA-256 of the Authorization header that asked for the sheet, so the proof is spendable only by
    -- the same access token that opened it. A second session of the same account cannot spend it.
    session_hash      VARCHAR(64) NOT NULL,
    -- ADOPT | GRANT | REVOKE | RECOVER. A step-up taken for one transition does not carry over to
    -- another, and the purposes that ask for no factor at all are refused before a sheet is minted.
    purpose           VARCHAR(16) NOT NULL,
    -- PASSKEY | PIN, written by the server from the ceremony it ran. Never PHONE_OTP: there is no arm
    -- of the sheet that sends a code, and a guard test fails the build if one appears.
    factor            VARCHAR(16) NOT NULL,
    -- When that credential came into being, which is what the fresh-factor hold weighs. Null when the
    -- account's PIN has no recorded set time, and then the hold has nothing to weigh rather than a
    -- sentinel to misread.
    factor_created_at TIMESTAMP WITH TIME ZONE,
    -- The challenge's own life, so a sheet left open is not a step-up hours later.
    expires_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    -- Set the first time the challenge endpoint spends it. Single use, and burned rather than deleted so
    -- a second attempt is refused rather than looking like a sheet that was never run.
    consumed_at       TIMESTAMP WITH TIME ZONE,
    created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- The lookup the challenge endpoint makes: this account, this purpose, unconsumed.
CREATE INDEX IF NOT EXISTS idx_account_authority_web_step_up_lookup
    ON account_authority_web_step_up (user_id, purpose);

CREATE INDEX IF NOT EXISTS idx_account_authority_web_step_up_expires
    ON account_authority_web_step_up (expires_at);
