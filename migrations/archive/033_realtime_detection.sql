-- Add realtime_enabled flag to detection rules
-- This allows users to enable/disable real-time detection per rule

ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS realtime_enabled BOOLEAN NOT NULL DEFAULT false;

-- Add event_hash column to alerts for deduplication
-- This stores a hash of the matched events to prevent duplicate alerts
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS event_hash TEXT;

-- Create index for fast deduplication lookups
CREATE INDEX IF NOT EXISTS idx_alerts_rule_event_hash 
ON alerts(rule_id, event_hash) 
WHERE event_hash IS NOT NULL;

-- Add comment explaining the columns
COMMENT ON COLUMN detection_rules.realtime_enabled IS 'When true, this rule is evaluated in real-time as logs are ingested';
COMMENT ON COLUMN alerts.event_hash IS 'Hash of matched events for deduplication - prevents duplicate alerts for same events';
