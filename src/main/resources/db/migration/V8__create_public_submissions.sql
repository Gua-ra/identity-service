-- Public, unauthenticated web-form submissions (support requests + beta-access
-- sign-ups) collected from gua.global. Notification is delivered out-of-band by
-- creating a GitHub issue in a private inbox repo; this table is the durable
-- record so a submission is never lost even if the GitHub call fails.
CREATE TABLE IF NOT EXISTS public_submissions (
    id UUID PRIMARY KEY,
    -- 'support' | 'beta'
    type TEXT NOT NULL,
    name TEXT,
    email TEXT NOT NULL,
    -- 'ios' | 'android' (beta only)
    platform TEXT,
    message TEXT,
    -- HMAC digest of the source IP (never the raw IP) for coarse abuse triage.
    source_ip_hash TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_public_submissions_type_created_at
    ON public_submissions (type, created_at);

CREATE INDEX IF NOT EXISTS idx_public_submissions_email
    ON public_submissions (email);
