-- Shared Searches Table
-- Stores search queries with short IDs for URL sharing

CREATE TABLE IF NOT EXISTS shared_searches (
    id VARCHAR(12) PRIMARY KEY,  -- Short alphanumeric ID (e.g., "abc123xyz")
    query TEXT NOT NULL,
    query_mode VARCHAR(10) NOT NULL DEFAULT 'piped',  -- 'piped' or 'sql'
    time_range_type VARCHAR(10) NOT NULL DEFAULT 'preset',  -- 'preset' or 'custom'
    time_range_preset VARCHAR(50),  -- e.g., 'Last 24 hours'
    time_range_start TIMESTAMPTZ,  -- For custom ranges
    time_range_end TIMESTAMPTZ,    -- For custom ranges
    created_at TIMESTAMPTZ DEFAULT NOW(),
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMPTZ
);

-- Index for quick lookups
CREATE INDEX IF NOT EXISTS idx_shared_searches_created_at ON shared_searches (created_at DESC);

-- Optional: Clean up old shared searches (can be run periodically)
-- DELETE FROM shared_searches WHERE created_at < NOW() - INTERVAL '90 days' AND access_count = 0;
