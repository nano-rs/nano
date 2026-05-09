-- Multi-node deployment hardening
-- Moves in-memory state to PostgreSQL for cross-node coordination

-- 1. Shared rate limiting table (replaces in-memory HashMaps)
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    key         TEXT NOT NULL,
    category    TEXT NOT NULL,
    tokens      INT NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (category, key)
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_window ON rate_limit_buckets (window_start);

-- 2. Ingestion pause flag (replaces AtomicBool shared via Arc)
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ingestion_paused BOOLEAN NOT NULL DEFAULT false;

-- 3. Tuning cooldown tracking (replaces in-memory HashMap)
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS last_tuned_at TIMESTAMPTZ;
