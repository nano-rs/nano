-- Track where agent_model_config rows came from so git-synced defaults
-- can be updated without clobbering user customisations.
--
-- 'upstream' = seeded/updated by model catalog sync (agent_defaults.yaml)
-- 'custom'   = manually configured by the user via UI/API
-- 'migration' = legacy rows from migration 040 (treated same as upstream)

-- Add source column
ALTER TABLE agent_model_config
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'migration';

-- Remove the hardcoded bedrock default on model_id — models come from git now
ALTER TABLE agent_model_config
    ALTER COLUMN model_id DROP DEFAULT;

-- Delete all migration-seeded agent configs so the catalog sync can
-- re-seed them from agent_defaults.yaml with the correct models.
-- Any rows a user explicitly configured via the UI will have been
-- updated through the API handler (which we'll set to source='custom').
DELETE FROM agent_model_config WHERE source = 'migration';
