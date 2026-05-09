-- Detection Event Tracking for Proper Deduplication
--
-- Problem: Rules with long lookback windows (e.g., 15m) running frequently (e.g., every 10s)
-- keep re-detecting the same events because the current event_hash approach only dedupes
-- identical event SETS, not individual events.
--
-- Solution: Track which individual events have been matched by each rule, and filter them
-- out in subsequent runs.

-- Create a table to track which events have been matched by which rules
CREATE TABLE IF NOT EXISTS detection_matched_events (
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rule_id, event_id)
);

-- Index for efficient cleanup of old entries
CREATE INDEX IF NOT EXISTS idx_detection_matched_events_timestamp 
    ON detection_matched_events(matched_at);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_detection_matched_events_event_time 
    ON detection_matched_events(rule_id, event_timestamp DESC);

COMMENT ON TABLE detection_matched_events IS 'Tracks individual events that have been matched by detection rules to prevent re-detection in overlapping lookback windows';
COMMENT ON COLUMN detection_matched_events.event_id IS 'Unique identifier for the event (typically log_id or computed hash)';
COMMENT ON COLUMN detection_matched_events.event_timestamp IS 'Original timestamp of the event for efficient cleanup';
COMMENT ON COLUMN detection_matched_events.matched_at IS 'When this event was first matched by this rule';

-- Cleanup function to remove old tracking entries (keep last 24 hours)
-- This prevents the table from growing indefinitely
CREATE OR REPLACE FUNCTION cleanup_old_matched_events()
RETURNS void AS $$
BEGIN
    DELETE FROM detection_matched_events
    WHERE matched_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Optional: Create a scheduled job to run cleanup daily
-- (Requires pg_cron extension - uncomment if available)
-- SELECT cron.schedule('cleanup-matched-events', '0 2 * * *', 'SELECT cleanup_old_matched_events()');
