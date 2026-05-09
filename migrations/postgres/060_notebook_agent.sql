-- ============================================================================
-- Migration 060: Add Notebook Agent Config
-- ============================================================================
-- Adds configuration for the Notebook AI agent that handles chat functionality
-- in investigation notebooks, including note analysis and suggestions.
-- ============================================================================

-- Add the notebook agent to the config table
INSERT INTO agent_model_config (
    agent_id,
    display_name,
    model_id,
    max_tokens,
    temperature,
    timeout_seconds,
    enabled
) VALUES (
    'notebook',
    'Notebook Agent',
    'gemini/gemini-2.0-flash',
    4096,
    0.7,
    120,
    true
) ON CONFLICT (agent_id) DO NOTHING;
