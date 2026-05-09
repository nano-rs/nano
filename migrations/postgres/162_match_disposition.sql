-- NAN-498: Per-match disposition.
--
-- Analysts triage a match and classify it: true_positive, false_positive,
-- benign, or leave it unclassified. The rule-level "Disposition FP" tile on
-- the Matches hero rolls these up over a time window. A per-match editor in
-- the detail pane is a follow-up.
--
-- Stored as a column (rather than a sidecar table like match_reviews) because
-- a disposition is intrinsic to the match itself — there's no "missing
-- disposition" state to model separately, and the FP-count rollup query is
-- substantially cheaper without a join.

BEGIN;

ALTER TABLE public.detection_matches
    ADD COLUMN IF NOT EXISTS disposition text NOT NULL DEFAULT 'unclassified';

ALTER TABLE public.detection_matches
    DROP CONSTRAINT IF EXISTS detection_matches_disposition_check;

ALTER TABLE public.detection_matches
    ADD CONSTRAINT detection_matches_disposition_check
    CHECK (disposition = ANY (ARRAY[
        'unclassified'::text,
        'true_positive'::text,
        'false_positive'::text,
        'benign'::text
    ]));

COMMENT ON COLUMN public.detection_matches.disposition IS
    'Analyst-assigned classification: unclassified|true_positive|false_positive|benign (NAN-498)';

-- Roll-up index: GET /api/rules/{id}/disposition-stats counts by disposition
-- per (rule_id, detected_at window). This index covers the common path.
CREATE INDEX IF NOT EXISTS idx_detection_matches_rule_disposition
    ON public.detection_matches (rule_id, disposition, detected_at DESC);

COMMIT;
