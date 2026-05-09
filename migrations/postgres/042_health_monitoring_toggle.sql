-- Add health monitoring toggle to system settings
ALTER TABLE system_settings
ADD COLUMN IF NOT EXISTS health_monitoring_enabled BOOLEAN NOT NULL DEFAULT true;
