-- The stable Gua account principal a passkey belongs to: the canonical accountId text, ga1 plus 55 base32
-- characters. It is derived from an immutable genesis object, carries no phone number, localpart or
-- homeserver, and never changes, so it is the one key an ownership question can be answered under.
--
-- Nullable, and deliberately not backfilled. A row without a principal has an MXID-derived user handle,
-- and the handle cannot be rewritten server side because the authenticator holds it and replays it on
-- every assertion, so a rewritten row would match no credential. Such rows are retired by deletion, and
-- the application refuses a credential with no principal rather than guessing one.
ALTER TABLE passkey_credentials
    ADD COLUMN IF NOT EXISTS account_principal VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_account_principal
    ON passkey_credentials (account_principal);

-- Numbered 19, not 13: V13 to V18 belong to the account-authority branch and are already applied on dev,
-- so reusing one would collide on version with a different checksum. A gap is harmless.
