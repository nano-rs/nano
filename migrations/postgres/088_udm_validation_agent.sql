-- UDM Validation Agent configuration
-- Validates AI-generated parser UDM field mappings for correctness
INSERT INTO agent_model_config (agent_id, display_name, model_id, max_tokens, temperature, timeout_seconds, enabled)
VALUES ('udm_validation', 'UDM Validation Agent', 'anthropic/claude-sonnet-4-5', 4096, 0.3, 60, true)
ON CONFLICT (agent_id) DO NOTHING;
