-- NAN-1251 (P3): retroactive revision flag.
--
-- When a new case escalates an entity to true_positive / needs_investigation,
-- prior cases for that same entity that were previously closed as
-- false_positive / benign are flagged for re-review ("wait, that last one was a
-- FP, but new behavior makes this a TP"). The flag is a persistent breadcrumb;
-- actually reopening the prior case is gated behind autonomy_mode = auto_close
-- (P4). In recommend-only we only flag + write a wall entry.

ALTER TABLE cases ADD COLUMN IF NOT EXISTS needs_review BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS needs_review_reason TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS needs_review_at TIMESTAMPTZ;

COMMENT ON COLUMN cases.needs_review IS
    'NAN-1251: set when a later case escalated a shared entity that this case had closed as FP/benign — suggests re-review.';
COMMENT ON COLUMN cases.needs_review_reason IS
    'Human-readable reason the case was flagged for re-review (which entity, which newer case).';
COMMENT ON COLUMN cases.needs_review_at IS
    'When the case was last flagged for re-review.';

-- Lookup index for the re-review surfacing (small partial index — most cases
-- are never flagged).
CREATE INDEX IF NOT EXISTS idx_cases_needs_review
    ON cases (needs_review_at DESC)
    WHERE needs_review = TRUE;
