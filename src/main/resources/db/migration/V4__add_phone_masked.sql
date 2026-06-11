-- Store a privacy-preserving masked form of the phone number (e.g. "••••1234")
-- alongside the irreversible HMAC digest. This is display-only: it reveals just
-- the last few digits and can NOT be reversed to the full number. The raw phone
-- is still never persisted.
ALTER TABLE directory_entries
    ADD COLUMN IF NOT EXISTS phone_masked VARCHAR(32);
