-- Fix Gemini model names: gemini-3-pro -> gemini-3-pro-preview
-- The original migration 040 was fixed but ON CONFLICT DO NOTHING prevented updates

-- Update available_models table
UPDATE available_models SET model_id = 'gemini/gemini-3-pro-preview' WHERE model_id = 'gemini/gemini-3-pro';
UPDATE available_models SET model_id = 'gemini/gemini-3-flash-preview' WHERE model_id = 'gemini/gemini-3-flash';

-- Update any agent configs using the old names
UPDATE agent_model_config SET model_id = 'gemini/gemini-3-pro-preview' WHERE model_id = 'gemini/gemini-3-pro';
UPDATE agent_model_config SET model_id = 'gemini/gemini-3-flash-preview' WHERE model_id = 'gemini/gemini-3-flash';
