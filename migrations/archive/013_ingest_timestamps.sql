-- Add ingest and enrich timestamps to logs table
-- Tracks when logs were received and enriched, separate from event timestamp

-- Add ingest_time column (when the log was stored in the database)
ALTER TABLE logs ADD COLUMN IF NOT EXISTS ingest_time TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Add enrich_time column (when enrichment was applied, nullable for non-enriched logs)
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enrich_time TIMESTAMPTZ;

-- Index on ingest_time for queries filtering by ingestion time
CREATE INDEX IF NOT EXISTS idx_logs_ingest_time ON logs (ingest_time DESC);

-- Comment on columns
COMMENT ON COLUMN logs.ingest_time IS 'Timestamp when the log was ingested into the database';
COMMENT ON COLUMN logs.enrich_time IS 'Timestamp when enrichment was applied (null if not enriched)';
