-- AI request counter table for volume-based rate limiting.
-- Single row per month (one deployment = one DB).
CREATE TABLE IF NOT EXISTS ai_request_counts (
    id SERIAL PRIMARY KEY,
    month TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(month)
);
