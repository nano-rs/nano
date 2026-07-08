-- NAN-1680 (P1f): drop the orphaned `prevalence_settings` singleton table.
--
-- This table (created in 001, seeded in 177) held prevalence config
-- (rarity_threshold, enable_*_tracking, retention_days, cache_ttl_seconds) but
-- is DEAD: no application code reads or writes it. Prevalence config is served
-- by `PrevalenceService::with_database_config` (backed by the shared settings
-- store) and the /api/prevalence/settings handlers operate on THAT config, not
-- this table. Verified: zero `FROM/INTO/UPDATE prevalence_settings` in the code
-- (only the 177 seed `INSERT ... ON CONFLICT DO NOTHING` touches it).
--
-- Idempotent (DROP ... IF EXISTS). Ordering is safe: on a fresh install the
-- table is created (001) → seeded (177) → dropped (here), netting it removed;
-- on an existing install it is simply dropped. CASCADE removes the table's
-- singleton index, pkey, and `updated_at` trigger; the trigger FUNCTION is a
-- separate object used only by that trigger, so it is dropped explicitly.

DROP TABLE IF EXISTS prevalence_settings CASCADE;
DROP FUNCTION IF EXISTS update_prevalence_settings_updated_at() CASCADE;
