-- Add 'team' to the valid tier values constraint
-- Team tier sits between Hobby and Starter (5 members, 10 GB/day, ~155 EPS)

ALTER TABLE system_settings
    DROP CONSTRAINT IF EXISTS check_tier_value;

ALTER TABLE system_settings
    ADD CONSTRAINT check_tier_value
    CHECK (tier IN ('unrestricted', 'hobby', 'team', 'starter', 'pro', 'enterprise'));
