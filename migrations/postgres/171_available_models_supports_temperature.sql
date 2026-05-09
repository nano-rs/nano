-- Add a `supports_temperature` capability flag to the model catalog so that
-- thinking-default models (Anthropic Opus 4.7, OpenAI GPT-5, OpenAI o-series)
-- can be flagged catalog-side via `models.yaml` rather than via a hard-coded
-- list in nanosiem code. The AI Gateway client omits the `temperature`
-- request field when this flag is `false`.

ALTER TABLE available_models
    ADD COLUMN IF NOT EXISTS supports_temperature BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN available_models.supports_temperature IS
    'Whether the model accepts the `temperature` parameter on chat completion '
    'requests. Set to false for thinking-default / reasoning models that '
    'reject it (Opus 4.7, GPT-5, o-series). Catalog-driven via models.yaml.';

-- Bootstrap: mark already-known thinking-default models from the migration
-- 040 seed (and any matching upstream-synced rows) so existing deployments
-- get correct behavior immediately, without waiting for a models.yaml sync.
-- The catalog sync continues to be the source of truth for future models —
-- this UPDATE is a one-time backfill of current state.
UPDATE available_models
SET supports_temperature = false
WHERE model_id LIKE '%opus-4-7%'
   OR model_id LIKE 'openai/gpt-5%'
   OR model_id LIKE 'azure/gpt-5%'
   OR model_id LIKE 'openai/o1%'
   OR model_id LIKE 'openai/o3%'
   OR model_id LIKE 'openai/o4%'
   OR model_id LIKE 'azure/o1%'
   OR model_id LIKE 'azure/o3%'
   OR model_id LIKE 'azure/o4%';
