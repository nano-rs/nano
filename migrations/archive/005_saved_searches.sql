-- Saved Searches Table
-- Requirements: 16.6

CREATE TABLE IF NOT EXISTS saved_searches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    query TEXT NOT NULL,  -- Piped query syntax
    time_range JSONB,  -- Optional default time range
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for saved searches
CREATE INDEX IF NOT EXISTS idx_saved_searches_name ON saved_searches (name);
CREATE INDEX IF NOT EXISTS idx_saved_searches_created_at ON saved_searches (created_at DESC);
