-- Migration: 085_shadow_agent_configs
-- Description: Add shadow investigation agents to agent_model_config and
--              remove orphaned triage_* rows left over from the removed triage system.

-- Insert shadow investigation agents (same defaults as other Sonnet 4.5 agents)
INSERT INTO agent_model_config (agent_id, display_name, model_id, max_tokens, temperature, timeout_seconds) VALUES
    ('shadow_hunting', 'Shadow Hunting Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 131072, 0.7, 180),
    ('shadow_narrative', 'Shadow Narrative Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 65536, 0.7, 120)
ON CONFLICT (agent_id) DO NOTHING;

-- Remove orphaned triage agents (triage system removed in commit 24cc69a)
DELETE FROM agent_model_config
WHERE agent_id IN (
    'triage_initial',
    'triage_correlation',
    'triage_enrichment',
    'triage_context',
    'triage_risk',
    'triage_verdict'
);
