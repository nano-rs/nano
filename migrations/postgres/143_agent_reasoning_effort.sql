-- Add reasoning_effort column to agent_model_config for models that support
-- configurable reasoning (e.g., "low", "medium", "high").
ALTER TABLE agent_model_config
    ADD COLUMN IF NOT EXISTS reasoning_effort TEXT;
