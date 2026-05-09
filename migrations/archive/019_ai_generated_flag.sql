-- Migration: Add ai_generated flag to detection_rules
-- Tracks whether a detection rule was created using AI assistance

ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS ai_generated BOOLEAN NOT NULL DEFAULT false;

-- Add index for filtering AI-generated rules
CREATE INDEX IF NOT EXISTS idx_detection_rules_ai_generated ON detection_rules (ai_generated);

COMMENT ON COLUMN detection_rules.ai_generated IS 'Whether this rule was created using AI assistance (meloD)';
