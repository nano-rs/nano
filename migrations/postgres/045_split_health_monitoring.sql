-- Split health monitoring into separate AI and feed monitoring toggles
-- AI monitoring checks provider connectivity (costs API credits)
-- Feed monitoring checks log source staleness (free - just DB queries)

-- Rename existing column to be specific to AI monitoring
ALTER TABLE system_settings
RENAME COLUMN health_monitoring_enabled TO ai_monitoring_enabled;

-- Add separate feed monitoring toggle (enabled by default)
ALTER TABLE system_settings
ADD COLUMN IF NOT EXISTS feed_monitoring_enabled BOOLEAN NOT NULL DEFAULT true;
