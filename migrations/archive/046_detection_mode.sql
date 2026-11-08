-- Migration: Add detection_mode and materialized_view_name to detection_rules
-- This migration adds support for triple-tier detection (real-time, near-real-time, scheduled)

-- Add detection_mode column with default 'scheduled' for backward compatibility
ALTER TABLE detection_rules 
ADD COLUMN detection_mode TEXT NOT NULL DEFAULT 'scheduled';

-- Add materialized_view_name column for real-time rules
ALTER TABLE detection_rules 
ADD COLUMN materialized_view_name TEXT;

-- Add comment explaining the detection modes
COMMENT ON COLUMN detection_rules.detection_mode IS 
'Detection execution mode: real-time (materialized views, 10-30s), near-real-time (micro-batch, 1-5min), or scheduled (cron, hourly/daily)';

COMMENT ON COLUMN detection_rules.materialized_view_name IS 
'Auto-generated materialized view name for real-time detection rules (null for other modes)';

-- Create index for filtering by detection mode
CREATE INDEX idx_detection_rules_detection_mode ON detection_rules(detection_mode);

-- Update existing rules to have 'scheduled' mode (already done by default, but explicit for clarity)
UPDATE detection_rules 
SET detection_mode = 'scheduled' 
WHERE detection_mode IS NULL OR detection_mode = '';

-- Add check constraint to ensure valid detection modes
ALTER TABLE detection_rules 
ADD CONSTRAINT check_detection_mode 
CHECK (detection_mode IN ('real-time', 'near-real-time', 'scheduled'));
