-- NAN-1685: AI provider monitoring must default OFF for NEW deployments (it polls
-- the configured AI provider on a schedule, which costs API tokens).
--
-- Migration 046 only did a one-time `UPDATE ... SET false` on existing rows; it
-- never changed the column DEFAULT. The `'default'` singleton row is seeded with
-- `INSERT INTO system_settings (id) VALUES ('default')` (no value given), so it
-- takes the column default — which was still `true`. Every fresh install
-- therefore came up with monitoring ENABLED and silently burned tokens.
--
-- Fix the default at the COLUMN level only. This affects NEW rows (fresh
-- installs) exclusively — `ALTER COLUMN SET DEFAULT` does NOT rewrite existing
-- rows, so current tenants keep whatever value they have set. Existing tenants
-- that want it off toggle it in Settings; we do not retroactively override a
-- deployment's setting here.
ALTER TABLE system_settings
    ALTER COLUMN ai_monitoring_enabled SET DEFAULT false;
