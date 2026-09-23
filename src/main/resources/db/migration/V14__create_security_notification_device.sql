-- ADM-009 gate 2: the out-of-band channel every window in that record depends on.
--
-- Additive and idempotent, in the style of V4-V13. Nothing here is read while
-- identity.authority.enabled is false: the register and remove endpoints answer 503, no row is ever
-- written, and this deployment behaves exactly as it did before the feature existed.
--
-- Why a table of this service's own rather than a Matrix pusher. A pusher lives under a session, and
-- completing an account recovery ends every session of the user, so the destination would die with
-- the thing the attacker just destroyed. The channel therefore has to be keyed on something the
-- install keeps across sign-out, which is the installation_id the client holds in its keychain or
-- keystore, and it has to live where no recovery path can reach it. It lives here because
-- AccountRecoveryService.complete writes identity_users and passkey_credentials only, and the
-- session sign-out runs in a different service against a different database, so neither can touch
-- this table even by accident.
--
-- Rollback: turn identity.authority.notifications.* off. The table may then be dropped
-- (DROP TABLE security_notification_device plus its flyway_schema_history row), but dropping it
-- silently removes the only channel gate 2 accepts, so the flag is the intended way back.

CREATE TABLE IF NOT EXISTS security_notification_device (
    id                      UUID        PRIMARY KEY,
    -- The account to warn. This table is keyed on the account holder and never on an accountId: the
    -- notification names a label and a time, so it needs no account object at all.
    user_id                 TEXT        NOT NULL,
    -- Client-generated, held in the keychain or keystore, stable across sign-out and re-login. The
    -- upsert key, and the whole reason this row outlives a recovery.
    installation_id         TEXT        NOT NULL,
    -- APNS | FCM. Chooses the transport.
    platform                TEXT        NOT NULL,
    -- The same app id the Matrix pusher already sends, so the APNs topic and the FCM project are
    -- picked from one constant rather than from a second one that can drift.
    app_id                  TEXT        NOT NULL,
    -- The destination, and the one sensitive column. Never logged.
    token                   TEXT        NOT NULL,
    -- SHA-256 of the token, so an audit line, a log or a support conversation can name a
    -- registration without printing it.
    token_fingerprint       TEXT        NOT NULL,
    -- The 16 label bytes a record may carry, which is the only thing a notification may name.
    device_label            TEXT,
    -- When present, removing this row from another install additionally needs a signature by a key
    -- the authority chain has active and unquarantined. This is the field that makes removal
    -- something a fresh post-recovery session cannot do.
    authority_device_key_b64 TEXT,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- Bounds retention and picks the live installs. A row older than the configured life stops being
    -- notified and is swept.
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- Retires a token the transport reports permanently unregistered, so a dead destination does not
    -- keep counting as a channel gate 2 would pass on.
    consecutive_failures    INT         NOT NULL DEFAULT 0,
    last_failure_at         TIMESTAMP WITH TIME ZONE
);

-- The upsert key. Without it every re-login adds a row and a stale token accumulates forever.
CREATE UNIQUE INDEX IF NOT EXISTS idx_security_notification_device_install
    ON security_notification_device (user_id, installation_id);

CREATE INDEX IF NOT EXISTS idx_security_notification_device_user
    ON security_notification_device (user_id);

-- A challenge minted for a purpose whose step-up is no factor at all has no factor to record.
--
-- V13 made the column NOT NULL, which was right for the four transitions it was written for and wrong
-- for the two purposes whose authorization is a signature rather than a factor: the browser-started
-- approval, which a device signs afterwards, and the notification binding added here. Both mint a
-- challenge with no factor behind it, so the insert failed outright. Widened rather than filled with a
-- sentinel: a row that claimed a factor nobody presented would be read by the fresh-factor hold.
ALTER TABLE account_authority_challenge
    ALTER COLUMN factor DROP NOT NULL;
