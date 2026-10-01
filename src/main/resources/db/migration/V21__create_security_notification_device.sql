-- Installs that receive security alerts.

CREATE TABLE IF NOT EXISTS security_notification_device (
    id                      UUID        PRIMARY KEY,
    user_id                 TEXT        NOT NULL,
    installation_id         TEXT        NOT NULL,
    platform                TEXT        NOT NULL,
    app_id                  TEXT        NOT NULL,
    token                   TEXT        NOT NULL,
    token_fingerprint       TEXT        NOT NULL,
    device_label            TEXT,
    authority_device_key_b64 TEXT,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    consecutive_failures    INT         NOT NULL DEFAULT 0,
    last_failure_at         TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_security_notification_device_install
    ON security_notification_device (user_id, installation_id);

CREATE INDEX IF NOT EXISTS idx_security_notification_device_user
    ON security_notification_device (user_id);

-- A challenge authorized by a device signature has no factor.
ALTER TABLE account_authority_challenge
    ALTER COLUMN factor DROP NOT NULL;
