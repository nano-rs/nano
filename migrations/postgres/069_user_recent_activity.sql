-- User Recent Activity Tracking
-- Unified table for tracking recently viewed items across the platform
-- Powers the "Continue Working" feature on the home dashboard

CREATE TABLE user_recent_activity (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_type VARCHAR(30) NOT NULL, -- 'detection', 'alert', 'case', 'dashboard'
    item_id UUID NOT NULL,
    item_title TEXT, -- Denormalized for quick display without joins
    item_metadata JSONB DEFAULT '{}', -- Extra context (severity, status, etc.)
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One entry per item per user - upsert on access
    UNIQUE(user_id, item_type, item_id)
);

-- Index for fetching user's recent items quickly
CREATE INDEX idx_user_recent_activity_user_time
    ON user_recent_activity(user_id, accessed_at DESC);

-- Index for cleanup queries
CREATE INDEX idx_user_recent_activity_accessed
    ON user_recent_activity(accessed_at);

-- Function to record activity with automatic pruning
-- Keeps only the 50 most recent items per type per user
CREATE OR REPLACE FUNCTION record_user_activity(
    p_user_id UUID,
    p_item_type VARCHAR(30),
    p_item_id UUID,
    p_item_title TEXT,
    p_item_metadata JSONB DEFAULT '{}'
) RETURNS VOID AS $$
BEGIN
    -- Upsert the activity record
    INSERT INTO user_recent_activity (user_id, item_type, item_id, item_title, item_metadata, accessed_at)
    VALUES (p_user_id, p_item_type, p_item_id, p_item_title, p_item_metadata, NOW())
    ON CONFLICT (user_id, item_type, item_id)
    DO UPDATE SET
        item_title = EXCLUDED.item_title,
        item_metadata = EXCLUDED.item_metadata,
        accessed_at = NOW();

    -- Prune old entries - keep only 50 most recent per type per user
    DELETE FROM user_recent_activity
    WHERE id IN (
        SELECT id FROM user_recent_activity
        WHERE user_id = p_user_id AND item_type = p_item_type
        ORDER BY accessed_at DESC
        OFFSET 50
    );
END;
$$ LANGUAGE plpgsql;

-- Cleanup function for old activity (called by scheduler)
-- Removes entries older than 30 days
CREATE OR REPLACE FUNCTION cleanup_old_user_activity() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_recent_activity
    WHERE accessed_at < NOW() - INTERVAL '30 days';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE user_recent_activity IS 'Tracks recently viewed items per user for Continue Working feature';
COMMENT ON COLUMN user_recent_activity.item_type IS 'Type: detection, alert, case, dashboard';
COMMENT ON COLUMN user_recent_activity.item_metadata IS 'Extra display info like severity, status, case_number';
