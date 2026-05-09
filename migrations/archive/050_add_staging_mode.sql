-- Migration: Add Staging Mode to Detection Rules
-- Description: Adds a "staging" mode for rules being worked on (not yet ready for testing)
-- 
-- Rule Modes:
-- - staging: Rule is being developed/edited, not executed at all (default for new rules)
-- - live: Rule is being tested against live data, matches logged but no alerts generated
-- - alerting: Rule is production-ready, matches generate real alerts

-- Drop the existing check constraint
ALTER TABLE detection_rules 
DROP CONSTRAINT IF EXISTS detection_rules_mode_check;

-- Add staging to the allowed values
ALTER TABLE detection_rules 
ADD CONSTRAINT detection_rules_mode_check 
CHECK (mode IN ('staging', 'live', 'alerting'));

-- Update the default to 'staging' for new rules
ALTER TABLE detection_rules 
ALTER COLUMN mode SET DEFAULT 'staging';

-- Add comment explaining the modes
COMMENT ON COLUMN detection_rules.mode IS 
'Rule mode: staging (being developed, not executed), live (testing, no alerts), alerting (production, generates alerts)';

-- Create index for filtering by mode
CREATE INDEX IF NOT EXISTS idx_detection_rules_mode ON detection_rules(mode);
