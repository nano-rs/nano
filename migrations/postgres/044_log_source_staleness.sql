-- Add staleness monitoring settings to log_sources
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS stale_alert_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS stale_threshold_minutes INTEGER NOT NULL DEFAULT 15;
