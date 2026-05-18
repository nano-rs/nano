-- NAN-840: repair drift between migrations/postgres-open/000_open_init.sql
-- and the cumulative state migrations 1–175 should have produced.
--
-- The open-init snapshot is the source-of-truth schema for fresh installs.
-- On boot, fresh installs apply the snapshot, then backfill _sqlx_migrations
-- rows 1–175 (marked applied without re-running). Any DDL change from those
-- migrations that wasn't captured in the snapshot becomes permanently absent
-- because the corresponding migration is never executed.
--
-- The audit (see NAN-840) found two such drifts. This migration fixes them
-- using ADD COLUMN IF NOT EXISTS so it's safe on:
--   * Fresh open-core installs    — columns missing, this adds them
--   * Fresh enterprise installs   — siem_health_reports columns missing
--                                   (overlay only no-ops via IF NOT EXISTS
--                                   on the CREATE TABLE); this adds them
--   * Existing tenants (any edition) that previously ran 158/166 in their
--     historical sequence — columns already present, ADD COLUMN IF NOT
--     EXISTS is a no-op
--
-- The CHECK constraints are added inside a DO block with a pg_constraint
-- existence guard so the migration is idempotent on tenants that already
-- have them (e.g., enterprise tenants that ran migration 158 historically).
--
-- We deliberately do NOT add the FK to playbooks(id). The playbooks table
-- is enterprise-only — it doesn't exist on open-core. The enterprise overlay
-- already adds the FK separately for enterprise tenants. Open-core code paths
-- don't dereference playbook_id when playbook_selector_mode = 'none' (the
-- default), so the absent FK is harmless on open-core.

-- ----------------------------------------------------------------------------
-- siem_health_reports — restore migration 166's columns
-- ----------------------------------------------------------------------------
ALTER TABLE siem_health_reports
    ADD COLUMN IF NOT EXISTS enrichment_score INTEGER,
    ADD COLUMN IF NOT EXISTS alerting_score INTEGER;

-- ----------------------------------------------------------------------------
-- detection_rules — restore migration 158's columns + CHECK constraints
-- (without the FK to playbooks — that's enterprise-only and the overlay
-- adds it separately for enterprise tenants).
-- ----------------------------------------------------------------------------
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS playbook_selector_mode TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS playbook_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'detection_rules_playbook_selector_mode_check'
          AND conrelid = 'public.detection_rules'::regclass
    ) THEN
        ALTER TABLE detection_rules
            ADD CONSTRAINT detection_rules_playbook_selector_mode_check
                CHECK (playbook_selector_mode IN ('none', 'specific', 'adaptive'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'detection_rules_playbook_id_mode_check'
          AND conrelid = 'public.detection_rules'::regclass
    ) THEN
        ALTER TABLE detection_rules
            ADD CONSTRAINT detection_rules_playbook_id_mode_check
                CHECK (
                    (playbook_selector_mode = 'specific' AND playbook_id IS NOT NULL)
                    OR (playbook_selector_mode IN ('none', 'adaptive') AND playbook_id IS NULL)
                );
    END IF;
END $$;
