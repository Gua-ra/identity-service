-- Head fields for cooldown, window extension and cancellation count.

ALTER TABLE account_authority_head
    ADD COLUMN IF NOT EXISTS cooldown_magic VARCHAR(4);

ALTER TABLE account_authority_head
    ADD COLUMN IF NOT EXISTS pending_extended BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE account_authority_head
    ADD COLUMN IF NOT EXISTS cancelled_count INTEGER NOT NULL DEFAULT 0;
