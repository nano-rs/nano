-- Add model catalog auto-sync scheduler toggle to system_settings
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS model_catalog_sync_scheduler_enabled BOOLEAN DEFAULT true;
