-- AI Triage Hints for Detection Rules
-- Adds per-rule hints to guide AI triage analysis

-- =============================================================================
-- ADD AI_TRIAGE_HINTS TO DETECTION_RULES TABLE
-- =============================================================================

-- AI triage hints stored as JSONB with structure:
-- {
--   "ignore_when": ["condition1", "condition2"],
--   "suspicious_when": ["condition1", "condition2"],
--   "context": "additional context string"
-- }
ALTER TABLE public.detection_rules
ADD COLUMN IF NOT EXISTS ai_triage_hints jsonb DEFAULT '{"ignore_when":[],"suspicious_when":[],"context":null}'::jsonb NOT NULL;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON COLUMN public.detection_rules.ai_triage_hints IS 'AI triage hints for guiding automated alert analysis - includes ignore_when, suspicious_when conditions and additional context';
