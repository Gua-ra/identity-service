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
