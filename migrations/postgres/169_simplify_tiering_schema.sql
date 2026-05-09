-- Simplify tiering schema (NAN-552)
--
-- Three time-based knobs collapse into one:
--   - tiering_hot_days       → DROPPED (move-to-warm timing is now driven by
--                              ClickHouse move_factor: volume size + ingest rate
--                              + move_factor jointly determine effective hot
--                              retention; not a customer setting)
--   - tiering_warm_days      → RENAMED to retention_days (this is the DELETE
--                              compliance cap; the only retention knob a
--                              customer actually wants to set)
--   - tiering_cold_enabled   → DROPPED (paired with cold_days)
--   - tiering_cold_days      → DROPPED (3rd-tier model not used; revisit if
--                              hot local → warm Wasabi → cold Wasabi-deep
--                              archive is ever a real product requirement)
--
-- move_factor is kept on the customer API for self-hosted / BYO-S3 users who
-- need to tune it for their bucket's latency. Managed/platform tenants don't
-- touch this codepath — their move_factor is set in the CHCluster CRD by
-- nano-main provisioning.

-- 0. Reconcile with the legacy `retention_days` column from 001_init.
--    `system_settings` has carried a `retention_days INT DEFAULT 90 NOT NULL`
--    since day 0 (the original retention setting, predating tiering). Migration
--    010 added `tiering_warm_days` alongside it without retiring the legacy
--    column. NAN-552's plan to rename `tiering_warm_days → retention_days`
--    can't proceed while the legacy column still exists.
--
--    Strategy: port the legacy value forward when it represents a real
--    customer choice (non-default value AND tiering not yet enabled), then
--    drop the legacy column so the rename below has somewhere to land.
UPDATE public.system_settings
   SET tiering_warm_days = retention_days
 WHERE id = 'default'
   AND tiering_enabled = false
   AND retention_days <> 90;

ALTER TABLE public.system_settings
    DROP COLUMN IF EXISTS retention_days;

-- 1. Rename retention column
ALTER TABLE public.system_settings
    RENAME COLUMN tiering_warm_days TO retention_days;

-- 2. Drop now-meaningless cross-column constraint, replace with bounded check
ALTER TABLE public.system_settings
    DROP CONSTRAINT IF EXISTS tiering_warm_days_check;

ALTER TABLE public.system_settings
    ADD CONSTRAINT retention_days_check
        CHECK (retention_days >= 1 AND retention_days <= 3650);

-- 3. Drop hot/cold knob columns and their constraints
ALTER TABLE public.system_settings
    DROP CONSTRAINT IF EXISTS tiering_hot_days_check;

ALTER TABLE public.system_settings
    DROP CONSTRAINT IF EXISTS tiering_cold_days_check;

ALTER TABLE public.system_settings
    DROP COLUMN IF EXISTS tiering_hot_days,
    DROP COLUMN IF EXISTS tiering_cold_enabled,
    DROP COLUMN IF EXISTS tiering_cold_days;

-- 4. Backfill move_factor for existing tiered deployments.
--
-- The pre-NAN-552 apply_ttl_rules issued a two-rule TTL:
--   ... TO VOLUME 'warm' ... DELETE
-- The MOVE rule was carrying the bleed-to-warm behavior for customers who
-- left tiering_move_factor at its default (0 = TTL-only). After NAN-552 the
-- TTL is DELETE-only and moves rely entirely on move_factor; with
-- move_factor=0, parts would never leave local disk.
--
-- Set a sane default (0.2 → start moving when free space < 20%, i.e. ~80%
-- used) for any deployment that had tiering enabled and was relying on the
-- old time-based MOVE. New deployments still default to 0 via the column
-- definition — apply_config() now refuses to apply with move_factor=0 +
-- enabled=true, forcing an explicit choice.
UPDATE public.system_settings
   SET tiering_move_factor = 0.2
 WHERE id = 'default'
   AND tiering_enabled = true
   AND tiering_move_factor = 0;

-- 5. Update column documentation
COMMENT ON COLUMN public.system_settings.retention_days IS
    'Days before data is deleted (compliance cap). Default: 365';
