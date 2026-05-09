-- Remove migration-seeded available_models so they come from upstream sync instead.
-- Models change too often to ship as static seeds; the model catalog sync service
-- fetches the latest catalog from GitHub on first setup and every 24h thereafter.
--
-- Agent model configs (agent_model_config) are intentionally kept — they define
-- agent structure and defaults. Their referenced model_ids will resolve once the
-- first upstream sync completes.

DELETE FROM available_models WHERE source = 'migration';
