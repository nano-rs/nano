-- Add AI Pipe agent configuration for inline LLM classification in nPL queries
INSERT INTO agent_model_config
  (agent_id, display_name, model_id, max_tokens, temperature, timeout_seconds, enabled)
VALUES
  ('ai_pipe', 'AI Pipe Agent',
   'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0',
   8192, 0.3, 60, true)
ON CONFLICT (agent_id) DO NOTHING;
