-- Migration: Add hint proposal support to tuning_proposals
-- This extends the auto-tuning system to support AI-generated hint proposals
-- as a fallback when query tuning isn't possible (critical rules, no viable pattern, etc.)

-- Add proposal type to distinguish between query tuning and hint updates
ALTER TABLE tuning_proposals
ADD COLUMN IF NOT EXISTS proposal_type TEXT NOT NULL DEFAULT 'query_tuning';

-- Add hint-related columns
ALTER TABLE tuning_proposals
ADD COLUMN IF NOT EXISTS current_hints JSONB,
ADD COLUMN IF NOT EXISTS proposed_hints JSONB,
ADD COLUMN IF NOT EXISTS hints_diff JSONB;

-- Add index for filtering by proposal type
CREATE INDEX IF NOT EXISTS idx_tuning_proposals_type
ON tuning_proposals(proposal_type, created_at DESC);

-- Add comment for documentation
COMMENT ON COLUMN tuning_proposals.proposal_type IS 'Type of proposal: query_tuning or hint_update';
COMMENT ON COLUMN tuning_proposals.current_hints IS 'Snapshot of current AiTriageHints (for hint_update proposals)';
COMMENT ON COLUMN tuning_proposals.proposed_hints IS 'Proposed new AiTriageHints (for hint_update proposals)';
COMMENT ON COLUMN tuning_proposals.hints_diff IS 'Diff showing added/removed hints: {added_ignore, removed_ignore, added_suspicious, removed_suspicious, context_changed}';
