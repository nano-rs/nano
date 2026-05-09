-- Model Catalog Sync
-- Enables syncing available model IDs from a git repository (nanos-sh/models)
-- so Nano can push model updates without SQL migrations.

-- Track whether each model came from upstream sync or was added manually
ALTER TABLE available_models
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'migration';

COMMENT ON COLUMN available_models.source IS 'Origin of this model: migration (SQL seed), upstream (git sync), or custom (user-added)';

-- Model catalog repository settings (stored in system_settings)
-- We reuse system_settings rather than a whole new table since there's only one upstream repo.
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS model_catalog_url TEXT DEFAULT 'https://github.com/nanos-sh/models',
    ADD COLUMN IF NOT EXISTS model_catalog_branch TEXT DEFAULT 'main',
    ADD COLUMN IF NOT EXISTS model_catalog_path TEXT DEFAULT 'models.yaml',
    ADD COLUMN IF NOT EXISTS model_catalog_last_synced_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS model_catalog_last_sync_status TEXT,
    ADD COLUMN IF NOT EXISTS model_catalog_last_sync_commit TEXT,
    ADD COLUMN IF NOT EXISTS model_catalog_last_sync_error TEXT;

COMMENT ON COLUMN system_settings.model_catalog_url IS 'GitHub repository URL for upstream model catalog';
