-- NAN-3463: restore objects that open-edition code reads but the open schema
-- never had.
--
-- `tools/nan749_split_open_overlay.py` classified `match_reviews` (core 161)
-- and `siem_health_finding_suppressions` (core 170) as enterprise tables, so
-- `migrations/postgres-open/000_open_init.sql` omits them and backfills 161
-- and 170 as already applied. Both back open surfaces:
--
--   * match_reviews: GET /api/rules/{id}/matches (LEFT JOIN) and
--     POST /api/matches/{id}/review, the Rule Matches page.
--   * siem_health_finding_suppressions: the SIEM Health page, which is
--     available in both editions (NAN-2357).
--
-- A fresh open database therefore returned 500 `relation ... does not exist`
-- on those pages.
--
-- `system_settings.internal_domain_suffixes` came only from enterprise
-- 9011200, yet the open settings page and the internal-domain readers
-- (domain prevalence, entity typing) read and write it, so open logged
-- `column "internal_domain_suffixes" does not exist` and could not save the
-- list. It is added here with 9011200's exact shape.
--
-- Each object is created with its original shape ONLY when it is absent.
-- Legacy databases ran 161/170, and enterprise databases also ran 9011200
-- and have the tenantized tables from 9000084 / 9000421, so on an enterprise
-- database this migration runs no DDL at all. That matters: enterprise tables can be owned by another role,
-- and PostgreSQL checks ownership before it evaluates IF NOT EXISTS (NAN-3398).
-- On a fresh enterprise database this runs before the overlay, which then
-- finds the core shape and tenantizes it exactly as on a legacy database.

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

    IF to_regclass('public.system_settings') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute
         WHERE attrelid = 'public.system_settings'::regclass
           AND attname = 'internal_domain_suffixes'
           AND NOT attisdropped
    ) THEN
        ALTER TABLE public.system_settings
            ADD COLUMN internal_domain_suffixes TEXT[] NOT NULL DEFAULT '{}'::TEXT[];
        ALTER TABLE public.system_settings
            ADD CONSTRAINT system_settings_internal_domain_suffixes_bound
            CHECK (cardinality(internal_domain_suffixes) <= 256) NOT VALID;
    END IF;
END
$migration$;
