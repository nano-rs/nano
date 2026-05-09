-- ============================================================================
-- Migration 136: Add Query Correction Agent Config
-- ============================================================================
-- Adds configuration for the AI agent that suggests corrected queries when
-- a user's search fails with a parse error, invalid field, or database error.
-- Uses a fast/cheap model since corrections are simple text transformations.
-- ============================================================================

INSERT INTO agent_model_config (
    agent_id,
    display_name,
    model_id,
    max_tokens,
    temperature,
    timeout_seconds,
    enabled
) VALUES (
    'query_correction',
    'Query Correction Agent',
    'gemini/gemini-3.1-flash-lite-preview',
    1024,
    0.2,
    20,
    true
) ON CONFLICT (agent_id) DO NOTHING;
