-- Organization tier-based restrictions
-- Adds tier configuration to system_settings for plan-based feature gating.
-- Default tier is 'unrestricted' (no limits) for dev/self-hosted deployments.

ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'unrestricted',
    ADD COLUMN IF NOT EXISTS tier_max_data_sources INTEGER,
    ADD COLUMN IF NOT EXISTS tier_max_detection_rules INTEGER,
    ADD COLUMN IF NOT EXISTS tier_max_team_members INTEGER,
    ADD COLUMN IF NOT EXISTS tier_max_daily_gb NUMERIC,
    ADD COLUMN IF NOT EXISTS tier_max_eps INTEGER,
    ADD COLUMN IF NOT EXISTS tier_api_access TEXT NOT NULL DEFAULT 'full',
    ADD COLUMN IF NOT EXISTS tier_sso_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS tier_ai_features TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS tier_limits_override JSONB;

-- Add constraint for valid tier values
ALTER TABLE system_settings
    ADD CONSTRAINT check_tier_value
    CHECK (tier IN ('unrestricted', 'hobby', 'starter', 'pro', 'enterprise'));

-- Add constraint for valid api_access values
ALTER TABLE system_settings
    ADD CONSTRAINT check_tier_api_access
    CHECK (tier_api_access IN ('readonly', 'full'));

-- Set defaults for the existing row
UPDATE system_settings
SET tier = 'unrestricted',
    tier_api_access = 'full',
    tier_sso_enabled = TRUE,
    tier_ai_features = '{}'
WHERE id = 'default';
