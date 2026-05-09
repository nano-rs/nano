-- Add 'startup' to the tier CHECK constraint
ALTER TABLE system_settings DROP CONSTRAINT IF EXISTS check_tier_value;

ALTER TABLE system_settings
    ADD CONSTRAINT check_tier_value
    CHECK (tier IN ('unrestricted', 'hobby', 'team', 'startup', 'starter', 'pro', 'enterprise'));
