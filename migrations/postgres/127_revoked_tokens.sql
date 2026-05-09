-- H8: Persist revoked access token JTIs to survive restarts
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti uuid PRIMARY KEY,
    expires_at bigint NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

-- Index for cleanup of expired entries
CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);
