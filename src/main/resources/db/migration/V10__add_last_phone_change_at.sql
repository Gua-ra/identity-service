-- Records when an account last changed its linked phone number so the change-phone
-- flow can enforce a cooldown between attempts (defense-in-depth against an attacker
-- who has gained a fresh session/reauth proof rapidly re-pointing the account).
-- Additive + idempotent, matching the project's migration conventions.
ALTER TABLE identity_users
    ADD COLUMN IF NOT EXISTS last_phone_change_at TIMESTAMP WITH TIME ZONE;
