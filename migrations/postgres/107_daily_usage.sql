-- Daily usage tracking for tier enforcement
-- Tracks ingestion volume and event counts per day for metering against tier limits.

CREATE TABLE IF NOT EXISTS daily_usage (
    date DATE NOT NULL,
    bytes_ingested BIGINT NOT NULL DEFAULT 0,
    events_ingested BIGINT NOT NULL DEFAULT 0,
    peak_eps INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (date)
);

-- Index for efficient range queries on usage history
CREATE INDEX IF NOT EXISTS idx_daily_usage_date ON daily_usage (date DESC);
