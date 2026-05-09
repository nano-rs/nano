-- Disable AI monitoring by default for existing deployments
-- This prevents unexpected API costs and rate limiting
-- Users can explicitly enable it in Settings if desired

-- Update any existing rows that have ai_monitoring_enabled = true to false
-- This is a safety measure to prevent rate limiting on existing deployments
UPDATE system_settings
SET ai_monitoring_enabled = false
WHERE id = 'default' AND ai_monitoring_enabled = true;

-- Note: This migration is safe to run multiple times
-- It only affects the default settings row
