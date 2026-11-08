-- Add event hash deduplication to detection_matches table
-- This prevents storing duplicate matches when rules run frequently with long lookback windows

-- Add event_hash column
ALTER TABLE detection_matches 
ADD COLUMN IF NOT EXISTS event_hash TEXT;

-- Create index for efficient lookups
CREATE INDEX IF NOT EXISTS idx_detection_matches_event_hash 
    ON detection_matches(event_hash);

-- Add unique constraint to prevent duplicates
-- Note: This will fail if there are existing duplicates in the table
-- If migration fails, you may need to clean up duplicates first
ALTER TABLE detection_matches 
ADD CONSTRAINT detection_matches_rule_event_unique 
UNIQUE (rule_id, event_hash);

COMMENT ON COLUMN detection_matches.event_hash IS 'SHA256 hash of matched_events for deduplication';
COMMENT ON CONSTRAINT detection_matches_rule_event_unique ON detection_matches IS 'Prevents storing duplicate matches for the same rule and events';
