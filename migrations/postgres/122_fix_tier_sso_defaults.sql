-- Fix tier_sso_enabled: make it nullable so NULL means "use tier default".
-- Previously it was NOT NULL DEFAULT TRUE, which meant every tier got SSO
-- regardless of whether the tier actually allows it (only Pro+ should).
-- The application now treats NULL as "use the hardcoded tier default" and
-- only non-NULL values as explicit overrides (same pattern as other tier columns).

-- Make column nullable and drop the old default
ALTER TABLE system_settings
    ALTER COLUMN tier_sso_enabled DROP NOT NULL,
    ALTER COLUMN tier_sso_enabled DROP DEFAULT;

-- Reset to NULL so all tiers fall back to their hardcoded defaults.
-- set_tier() will write the correct explicit value on next tier change.
UPDATE system_settings
SET tier_sso_enabled = NULL
WHERE id = 'default';
