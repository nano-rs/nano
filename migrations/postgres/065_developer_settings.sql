-- Developer settings for scheduler control
-- Allows disabling background schedulers during development/testing
-- to prevent ClickHouse Cloud from being kept alive

-- Add scheduler enable/disable columns to system_settings
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS detection_scheduler_enabled BOOLEAN DEFAULT true,
    ADD COLUMN IF NOT EXISTS tuning_scheduler_enabled BOOLEAN DEFAULT true,
    ADD COLUMN IF NOT EXISTS enrichment_sync_scheduler_enabled BOOLEAN DEFAULT true,
    ADD COLUMN IF NOT EXISTS custom_enrichment_scheduler_enabled BOOLEAN DEFAULT true;

-- Add comments for documentation
COMMENT ON COLUMN system_settings.detection_scheduler_enabled IS 'Enable/disable detection rule scheduler (5s interval, queries ClickHouse)';
COMMENT ON COLUMN system_settings.tuning_scheduler_enabled IS 'Enable/disable tuning scheduler (metrics, baselines, thresholds - queries ClickHouse)';
COMMENT ON COLUMN system_settings.enrichment_sync_scheduler_enabled IS 'Enable/disable enrichment auto-sync scheduler (may query ClickHouse for cleanup)';
COMMENT ON COLUMN system_settings.custom_enrichment_scheduler_enabled IS 'Enable/disable custom enrichment scheduler (INSERT/SELECT for enrichments)';
