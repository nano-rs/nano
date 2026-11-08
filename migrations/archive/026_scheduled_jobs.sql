-- Scheduled Jobs Table
-- Migration: 026_scheduled_jobs.sql
-- Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7
--
-- Stores scheduled data fetch jobs that automatically retrieve data
-- from remote URLs on a cron schedule for log ingestion or lookup table updates.

CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    cron_expression VARCHAR(100) NOT NULL,      -- Cron schedule (e.g., '0 0 * * *' for daily)
    url TEXT NOT NULL,                          -- Remote URL to fetch data from
    auth_headers JSONB,                         -- Optional authentication headers (encrypted at rest)
    destination_type VARCHAR(50) NOT NULL,      -- 'logs' or 'lookup'
    destination_config JSONB NOT NULL,          -- Destination-specific config (source_type, table_name, mode)
    parser_config JSONB NOT NULL,               -- Parser configuration (format, delimiter, etc.)
    retry_max INT DEFAULT 3,                    -- Maximum retry attempts
    retry_delay_secs INT DEFAULT 60,            -- Delay between retries in seconds
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(50),                -- 'success', 'failed', 'running'
    last_run_error TEXT,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for finding enabled jobs
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_enabled ON scheduled_jobs(enabled);

-- Index for finding jobs due to run
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_next_run ON scheduled_jobs(next_run_at) WHERE enabled = true;

-- Index for listing jobs by creation time
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_created ON scheduled_jobs(created_at DESC);

-- Composite index for scheduler polling (enabled jobs ordered by next run time)
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_poll ON scheduled_jobs(enabled, next_run_at) WHERE enabled = true;

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_scheduled_jobs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scheduled_jobs_updated_at ON scheduled_jobs;
CREATE TRIGGER scheduled_jobs_updated_at
    BEFORE UPDATE ON scheduled_jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_scheduled_jobs_updated_at();
