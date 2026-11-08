-- Search History per user
-- Stores search queries executed by each user for quick recall

CREATE TABLE IF NOT EXISTS search_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    query TEXT NOT NULL,
    query_mode VARCHAR(10) NOT NULL DEFAULT 'piped', -- 'piped' or 'sql'
    time_range_type VARCHAR(20) NOT NULL DEFAULT 'preset', -- 'preset' or 'custom'
    time_range_preset VARCHAR(50), -- e.g., 'Last 24 hours'
    time_range_start TIMESTAMPTZ,
    time_range_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast user history lookup (most recent first)
CREATE INDEX idx_search_history_user_created ON search_history(user_id, created_at DESC);

-- Limit history per user (keep last 100 entries via trigger)
CREATE OR REPLACE FUNCTION limit_search_history()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM search_history
    WHERE id IN (
        SELECT id FROM search_history
        WHERE user_id = NEW.user_id
        ORDER BY created_at DESC
        OFFSET 100
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_limit_search_history
AFTER INSERT ON search_history
FOR EACH ROW
EXECUTE FUNCTION limit_search_history();

-- User preference for history enabled/disabled
ALTER TABLE users ADD COLUMN IF NOT EXISTS search_history_enabled BOOLEAN NOT NULL DEFAULT true;
