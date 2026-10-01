-- One-time step-up proofs from the hosted web sheet.

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
