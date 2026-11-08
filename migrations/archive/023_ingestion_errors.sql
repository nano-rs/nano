-- Ingestion Error Tracking
-- Track parsing and storage errors for monitoring feed health

-- Table to track ingestion errors
CREATE TABLE IF NOT EXISTS ingestion_errors (
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    id BIGSERIAL,
    error_type TEXT NOT NULL, -- 'parse_error', 'storage_error', 'enrichment_error'
    source_type TEXT, -- Feed name if identifiable
    raw_content TEXT, -- Original log content that failed
    error_message TEXT NOT NULL,
    error_details JSONB DEFAULT '{}' -- Additional error context
);

-- Convert to TimescaleDB hypertable for efficient time-series storage
-- Note: Must be done before creating indexes
SELECT create_hypertable('ingestion_errors', 'timestamp', 
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => true
);

-- Indexes for time-based queries (created after hypertable)
CREATE INDEX IF NOT EXISTS idx_ingestion_errors_timestamp ON ingestion_errors (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ingestion_errors_source_type ON ingestion_errors (source_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ingestion_errors_type ON ingestion_errors (error_type, timestamp DESC);

-- Add compression policy (compress chunks older than 7 days)
SELECT add_compression_policy('ingestion_errors', INTERVAL '7 days', if_not_exists => true);

-- Add retention policy (drop chunks older than 90 days)
SELECT add_retention_policy('ingestion_errors', INTERVAL '90 days', if_not_exists => true);