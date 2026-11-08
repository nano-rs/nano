-- Migration: Add rule mode and live_match_count to detection_rules
-- This supports the bake-in workflow where rules start in "live" mode
-- and are promoted to "alerting" mode after tuning

-- Add mode column with default 'live' for new rules
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'live' 
CHECK (mode IN ('live', 'alerting'));

-- Add live_match_count for tracking matches during bake-in period
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS live_match_count BIGINT NOT NULL DEFAULT 0;

-- Add narrative for AI-generated explanations
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS narrative TEXT;

-- Add reference_url for external documentation
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS reference_url TEXT;

-- Add author field
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS author TEXT;

-- Add tags for flexible categorization
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

-- Update existing rules to 'alerting' mode (they were already in production)
UPDATE detection_rules SET mode = 'alerting' WHERE mode = 'live';

-- Add index for filtering by mode
CREATE INDEX IF NOT EXISTS idx_detection_rules_mode ON detection_rules (mode);

-- Add composite index for enabled + mode queries
CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled_mode ON detection_rules (enabled, mode);

-- Add GIN index for tags array search
CREATE INDEX IF NOT EXISTS idx_detection_rules_tags ON detection_rules USING GIN (tags);

-- Add index for author
CREATE INDEX IF NOT EXISTS idx_detection_rules_author ON detection_rules (author);

COMMENT ON COLUMN detection_rules.mode IS 'Rule mode: live (bake-in, no alerts) or alerting (production)';
COMMENT ON COLUMN detection_rules.live_match_count IS 'Count of matches during live/bake-in mode for tuning';
COMMENT ON COLUMN detection_rules.narrative IS 'AI-generated narrative explaining what the rule detects and why it matters';
COMMENT ON COLUMN detection_rules.reference_url IS 'Reference URL for more information (blog post, CVE, threat intel)';
COMMENT ON COLUMN detection_rules.author IS 'Author of the detection rule';
COMMENT ON COLUMN detection_rules.tags IS 'Tags for categorization beyond MITRE (e.g., ransomware, apt, insider-threat)';
