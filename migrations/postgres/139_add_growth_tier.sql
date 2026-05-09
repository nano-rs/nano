-- Add 'growth' to the tier CHECK constraint and 'none' to api_access
ALTER TABLE system_settings DROP CONSTRAINT IF EXISTS check_tier_value;

ALTER TABLE system_settings
    ADD CONSTRAINT check_tier_value
    CHECK (tier IN ('unrestricted', 'hobby', 'startup', 'growth', 'team', 'starter', 'pro', 'enterprise'));

ALTER TABLE system_settings DROP CONSTRAINT IF EXISTS check_tier_api_access;

ALTER TABLE system_settings
    ADD CONSTRAINT check_tier_api_access
    CHECK (tier_api_access IN ('none', 'readonly', 'full'));
