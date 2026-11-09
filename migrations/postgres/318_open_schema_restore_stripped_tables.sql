-- Open-core relations: restore two tables the open schema never had.
--
-- The open fresh-init snapshot (migrations/postgres-open/000_open_init.sql,
-- baseline 175) was split by a script that classified `match_reviews`
-- (core 161) and `siem_health_finding_suppressions` (core 170) as
-- enterprise-only, so the snapshot omits them while 161 and 170 are marked
-- applied and never run. Both back open surfaces:
--
--   * match_reviews: the Rule Matches list (GET /api/rules/{id}/matches
--     joins it) and the per-match review toggle.
--   * siem_health_finding_suppressions: suppress / undo on the open SIEM
--     health page.
--
-- Every fresh open v2 install therefore answered those pages with
-- "relation does not exist". This is the v2 port of the lake-line NAN-3463
-- repair, restricted to the relations v2 open code reads.
--
-- Each table is created with its original shape only when it is absent:
--   * fresh open installs, and open installs that already ran v2.0.0, gain it;
--   * legacy tenants (which ran 161/170) and enterprise installs (whose
--     overlay creates the same tables under the same object names) run no DDL.
-- The existence check comes first on purpose: PostgreSQL checks table
-- ownership before it evaluates IF NOT EXISTS on an index, and enterprise
-- tables can be owned by another role.

DO $migration$
BEGIN
    IF to_regclass('public.match_reviews') IS NULL THEN
        CREATE TABLE public.match_reviews (
            match_id    uuid PRIMARY KEY REFERENCES public.detection_matches(id) ON DELETE CASCADE,
            reviewed_at timestamp with time zone NOT NULL DEFAULT now(),
            reviewed_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
            note        text
        );
        COMMENT ON TABLE public.match_reviews IS
            'Per-match review state set by analysts via POST /api/matches/{id}/review';
        COMMENT ON COLUMN public.match_reviews.reviewed_by IS
            'User who marked the match reviewed (NULL if user later deleted)';
        COMMENT ON COLUMN public.match_reviews.note IS
            'Optional analyst note captured at review time';
        CREATE INDEX idx_match_reviews_reviewed_at
            ON public.match_reviews (reviewed_at DESC);
    END IF;

    IF to_regclass('public.siem_health_finding_suppressions') IS NULL THEN
        CREATE TABLE public.siem_health_finding_suppressions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_signature TEXT NOT NULL,
            title TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_by UUID NOT NULL REFERENCES public.users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deactivated_at TIMESTAMPTZ,
            deactivated_by UUID REFERENCES public.users(id)
        );
        CREATE UNIQUE INDEX idx_siem_health_finding_suppressions_active_signature
            ON public.siem_health_finding_suppressions (finding_signature)
            WHERE deactivated_at IS NULL;
        CREATE INDEX idx_siem_health_finding_suppressions_active
            ON public.siem_health_finding_suppressions (created_at DESC)
            WHERE deactivated_at IS NULL;
    END IF;
END
$migration$;
