CREATE TABLE IF NOT EXISTS identity_users (
    id UUID PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    pin_hash TEXT,
    pin_set_at TIMESTAMP WITH TIME ZONE,
    pin_reset_requested_at TIMESTAMP WITH TIME ZONE,
    pin_failure_count INTEGER NOT NULL DEFAULT 0,
    pin_locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    id UUID PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_name TEXT,
    platform TEXT,
    app_version TEXT,
    last_ip TEXT,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_trusted_devices_user_device UNIQUE (user_id, device_id)
);
