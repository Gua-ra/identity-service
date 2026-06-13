-- Contact discovery opt-out: when FALSE the account never appears in
-- /directory/lookup results (friends uploading their address book will not
-- see this user), while normal messaging keeps working. Defaults to TRUE to
-- match the WhatsApp-style "findable by people who have my number" baseline.
ALTER TABLE directory_entries
    ADD COLUMN IF NOT EXISTS discoverable BOOLEAN NOT NULL DEFAULT TRUE;
