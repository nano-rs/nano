-- Add default time range preference to users table
-- Allows users to set their preferred default time range for searches

ALTER TABLE users ADD COLUMN IF NOT EXISTS default_time_range VARCHAR(30)
    DEFAULT 'last_24_hours'
    CHECK (default_time_range IN (
        'last_15_minutes',
        'last_hour',
        'last_4_hours',
        'last_24_hours',
        'last_7_days',
        'last_30_days'
    ));

COMMENT ON COLUMN users.default_time_range IS 'Default time range preset for searches';
