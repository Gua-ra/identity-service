-- Adds stable account-principal ownership for passkeys.
-- Existing credentials are not backfilled because authenticator-held user handles cannot be rewritten server-side.

ALTER TABLE passkey_credentials
    ADD COLUMN IF NOT EXISTS account_principal VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_account_principal
    ON passkey_credentials (account_principal);
