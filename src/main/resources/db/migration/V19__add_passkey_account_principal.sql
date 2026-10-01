-- The stable Gua account principal a passkey belongs to.
--
-- Passkeys were keyed on the Matrix user id: passkey_credentials.user_id held an MXID and the WebAuthn
-- user handle was that MXID's own bytes. That binds a credential to a name which contains the account's
-- localpart and its homeserver domain, so it cannot survive a placement change, it leaks both into every
-- credential synced to the holder's password manager, and it made ownership questions (does this account
-- have a passkey, which credentials are excluded from registration, which ones must a completed recovery
-- revoke) answerable only under the current MXID.
--
-- account_principal is the canonical accountId text, ga1 + 55 base32 characters. It is derived from an
-- immutable genesis object, contains no phone number, no localpart and no homeserver, and never changes.
--
-- Nullable on purpose, and not backfilled here. Every row written before this migration carries an
-- MXID-derived handle whose bytes cannot be rewritten: the authenticator holds the handle and returns it
-- on assertion, so a server-side rewrite would produce a row no credential can ever match. Those rows are
-- retired by deletion, not migration, which is safe because the population is pre-launch and every holder
-- has another factor. The application refuses a credential with no principal rather than guessing one.
ALTER TABLE passkey_credentials
    ADD COLUMN IF NOT EXISTS account_principal VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_account_principal
    ON passkey_credentials (account_principal);

-- Numbered 19 rather than 13 deliberately. The account-authority feature branch occupies V13 to V18 and
-- its migrations are already applied on the dev database, so reusing any of those versions would collide
-- on version with a different checksum. A gap is harmless: Flyway applies what it finds, in order.
