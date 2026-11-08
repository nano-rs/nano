-- Add last_match_at timestamp to detection rules
-- This tracks when the rule last matched an event (regardless of mode)
-- Separate from last_run_at which tracks when the rule was last executed

ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS last_match_at TIMESTAMPTZ;

-- Create index for sorting by last match
CREATE INDEX IF NOT EXISTS idx_detection_rules_last_match_at ON detection_rules (last_match_at DESC NULLS LAST);

-- Update existing rules: set last_match_at to the most recent alert created_at for each rule
UPDATE detection_rules dr
SET last_match_at = (
    SELECT MAX(a.created_at)
    FROM alerts a
    WHERE a.rule_id = dr.id
)
WHERE EXISTS (
    SELECT 1 FROM alerts a WHERE a.rule_id = dr.id
);
