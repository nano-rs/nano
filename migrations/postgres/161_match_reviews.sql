-- NAN-494: Per-match review state.
--
-- Analysts triage a match and flag it as "reviewed" so it disappears from the
-- unread queue and shows a chip in the detail pane. We keep the review state
-- in a sidecar table (rather than a column on detection_matches) so we can
-- track who reviewed it, when, and capture an optional note without bloating
-- the matches table itself.
--
-- One review per match: PRIMARY KEY (match_id). Re-marking updates in place.

BEGIN;

CREATE TABLE IF NOT EXISTS public.match_reviews (
    match_id    uuid PRIMARY KEY REFERENCES public.detection_matches(id) ON DELETE CASCADE,
    reviewed_at timestamp with time zone NOT NULL DEFAULT now(),
    reviewed_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    note        text
);

COMMENT ON TABLE public.match_reviews IS 'Per-match review state set by analysts via POST /api/matches/{id}/review';
COMMENT ON COLUMN public.match_reviews.reviewed_by IS 'User who marked the match reviewed (NULL if user later deleted)';
COMMENT ON COLUMN public.match_reviews.note IS 'Optional analyst note captured at review time';

CREATE INDEX IF NOT EXISTS idx_match_reviews_reviewed_at
    ON public.match_reviews (reviewed_at DESC);

COMMIT;
