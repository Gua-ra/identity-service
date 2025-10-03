CREATE TABLE IF NOT EXISTS directory_entries (
    id UUID PRIMARY KEY,
    phone_digest VARCHAR(64) NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    display_name TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
