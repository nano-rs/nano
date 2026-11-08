-- Query Explanations Cache
-- Stores AI-generated explanations for queries so they can be shared via URLs

CREATE TABLE IF NOT EXISTS query_explanations (
    -- SHA256 hash of the normalized query (lowercase, trimmed)
    query_hash VARCHAR(64) PRIMARY KEY,
    -- The original query text
    query TEXT NOT NULL,
    -- Query mode (piped, sql)
    query_mode VARCHAR(10) NOT NULL DEFAULT 'piped',
    -- Natural language prompt that generated this query (if any)
    natural_language_prompt TEXT,
    -- AI explanation text
    explanation TEXT,
    -- Reasoning steps as JSON array
    reasoning_steps JSONB,
    -- Fields used in the query
    fields_used JSONB,
    -- Generated SQL (for piped queries)
    generated_sql TEXT,
    -- Query complexity (simple, moderate, complex)
    complexity VARCHAR(20),
    -- Suggested time range description
    suggested_time_range TEXT,
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    -- Access tracking
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMPTZ
);

-- Index for cleanup queries
CREATE INDEX IF NOT EXISTS idx_query_explanations_created_at ON query_explanations (created_at);
CREATE INDEX IF NOT EXISTS idx_query_explanations_last_accessed ON query_explanations (last_accessed_at);

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_query_explanations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at
DROP TRIGGER IF EXISTS trigger_query_explanations_updated_at ON query_explanations;
CREATE TRIGGER trigger_query_explanations_updated_at
    BEFORE UPDATE ON query_explanations
    FOR EACH ROW
    EXECUTE FUNCTION update_query_explanations_updated_at();

-- Comment explaining the table
COMMENT ON TABLE query_explanations IS 'Cache for AI-generated query explanations, enabling shared URLs to include the AI reasoning';
COMMENT ON COLUMN query_explanations.query_hash IS 'SHA256 hash of normalized query for deduplication';
COMMENT ON COLUMN query_explanations.reasoning_steps IS 'JSON array of reasoning steps from meloD';
