-- Detection Matches Table
-- Stores individual detection matches for review, regardless of rule mode
-- This allows users to see what actually matched when rules were running

CREATE TABLE IF NOT EXISTS detection_matches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    matched_events JSONB NOT NULL DEFAULT '[]',
    event_count INTEGER NOT NULL DEFAULT 0,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_detection_matches_rule_id 
    ON detection_matches(rule_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_detection_matches_detected_at 
    ON detection_matches(detected_at DESC);

-- Index for time range queries (removed WHERE clause since NOW() is not IMMUTABLE)
-- PostgreSQL will still efficiently use this index for time range queries
CREATE INDEX IF NOT EXISTS idx_detection_matches_rule_time 
    ON detection_matches(rule_id, detected_at DESC);

COMMENT ON TABLE detection_matches IS 'Stores individual detection matches for all rule modes (staging, live, alerting) so they can be reviewed';
COMMENT ON COLUMN detection_matches.matched_events IS 'JSONB array of events that triggered this detection';
COMMENT ON COLUMN detection_matches.event_count IS 'Number of events in this match (for quick filtering)';
