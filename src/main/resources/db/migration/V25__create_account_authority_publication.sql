-- Delivery state of published chain heads.

CREATE TABLE IF NOT EXISTS account_authority_publication (
    account_id     VARCHAR(64) NOT NULL PRIMARY KEY,
    head_seq       BIGINT      NOT NULL,
    head_hash      VARCHAR(64) NOT NULL,
    homeserver_id  VARCHAR(64) NOT NULL,
    record_b64     TEXT        NOT NULL,
    signature_b64  TEXT        NOT NULL,
    payload_hash   VARCHAR(64) NOT NULL,
    issued_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after      TIMESTAMP WITH TIME ZONE NOT NULL,
    signed_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    confirmed_at   TIMESTAMP WITH TIME ZONE,
    attempts       INTEGER     NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_account_authority_publication_unconfirmed
    ON account_authority_publication (confirmed_at);
