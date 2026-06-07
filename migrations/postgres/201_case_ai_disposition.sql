-- NAN-1251: AI Tier-1 triage — structured shadow-investigation verdict on the case.
--
-- The shadow investigator already emits a verdict (TP / FP / needs-investigation)
-- as free-text narrative parked in the notebook. These columns capture that verdict
-- in structured form, written back to the case so it can be surfaced in the inbox,
-- fed into cross-case entity memory, and (optionally, behind policy) acted on.
--
-- These are kept DISTINCT from the human `disposition` column: `ai_disposition` is
-- the machine's recommendation, `disposition` remains the analyst's call. In
-- recommend-only mode the AI never touches `disposition`.

ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_disposition VARCHAR(20);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_confidence NUMERIC(3, 2);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_recommended_action TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_key_evidence JSONB;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS ai_triaged_at TIMESTAMPTZ;

COMMENT ON COLUMN cases.ai_disposition IS
    'Shadow-investigator structured verdict: true_positive | false_positive | benign | inconclusive | needs_investigation. Distinct from human disposition (NAN-1251).';
COMMENT ON COLUMN cases.ai_confidence IS
    'AI self-reported verdict confidence, 0.00-1.00. NOT calibrated probability — auto-close gates on agreement signals, not this alone (NAN-1251).';
COMMENT ON COLUMN cases.ai_recommended_action IS
    'AI recommended next action for the analyst (free text).';
COMMENT ON COLUMN cases.ai_key_evidence IS
    'JSON array of the concrete evidence strings the AI cited for its verdict.';
COMMENT ON COLUMN cases.ai_triaged_at IS
    'When the AI last wrote a structured verdict to this case.';

-- Partial index for the "Must Investigate" inbox bucket: open cases the AI flagged
-- as actionable (TP / needs-investigation) that a human has not yet dispositioned.
CREATE INDEX IF NOT EXISTS idx_cases_ai_escalated
    ON cases (ai_triaged_at DESC)
    WHERE ai_disposition IN ('true_positive', 'needs_investigation')
      AND disposition IS NULL;
