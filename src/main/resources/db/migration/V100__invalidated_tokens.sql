CREATE TABLE IF NOT EXISTS invalidated_tokens (
    id uuid PRIMARY KEY,
    token text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_invalidated_tokens_expires
    ON invalidated_tokens(expires_at);
