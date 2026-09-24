-- ADM-009 review follow-ups on the head row. Three columns, each closing a hole the review found in the
-- state the head was keeping.
--
-- Additive and idempotent, like V13-V16, and read only while identity.authority.enabled is true. With the
-- flag off nothing writes them and every authority endpoint still answers 503.
--
-- Rollback: turn identity.authority.* off. The columns may then be dropped, but they do not need to be.

-- The shape the cooldown was written for. One cooldown column with nothing beside it refused every shape at
-- once, which is the absolute freeze ADM-009 decision 3 rejected, reached from the other side: the owner's
-- own successful objection froze their grant, revocation, self-revocation and recovery for a full window
-- each time, while the intruder who opened the cancelled record paid only their own doubling backoff.
ALTER TABLE account_authority_head
    ADD COLUMN IF NOT EXISTS cooldown_magic VARCHAR(4);
