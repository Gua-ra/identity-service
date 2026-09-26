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

-- Whether the pending record's window has already been extended once (decision 7). An active device's
-- opposition to a recovery signed by the committed recovery authority key extends the window once and raises
-- the notification, and nothing more. Nothing counted the one, and nothing else bounds it: an Oppose costs no
-- factor and no backoff, and no part of the staleness check changes when a window moves, so the same
-- objection was re-submittable until the account was postponed out of its own recovery.
ALTER TABLE account_authority_head
    ADD COLUMN IF NOT EXISTS pending_extended BOOLEAN NOT NULL DEFAULT FALSE;

-- How many records this account has had cancelled (decision 4's bounds on free oppositions). A cancelled
-- record now gives its slot back, so a retry lands at the position it held and replaces the row; the count
-- has to live somewhere a retry does not erase, or the second opposition would be free again after every
-- retry and a stolen bearer session could veto an account out of ever holding authority.
ALTER TABLE account_authority_head
    ADD COLUMN IF NOT EXISTS cancelled_count INTEGER NOT NULL DEFAULT 0;
