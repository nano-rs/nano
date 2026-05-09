-- Add Concierge agent configuration for home page AI orchestrator
-- Uses a fast/cheap model for intent classification, then delegates to specialized agents
INSERT INTO agent_model_config
  (agent_id, display_name, model_id, max_tokens, temperature, timeout_seconds, enabled)
VALUES
  ('concierge', 'Concierge Agent',
   'gemini/gemini-3.1-flash-lite-preview',
   1024, 0.1, 30, true)
ON CONFLICT (agent_id) DO NOTHING;
