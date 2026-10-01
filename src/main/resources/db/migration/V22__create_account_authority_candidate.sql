-- Device keys waiting to be granted.

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
