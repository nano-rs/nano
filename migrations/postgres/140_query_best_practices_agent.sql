-- ============================================================================
-- Migration 140: Add Query Best Practices Agent Config
-- ============================================================================
-- Adds configuration for the AI agent that reviews successful complex queries
-- and suggests optimizations. Uses a fast/cheap model since reviews are
-- lightweight text analysis. Shares the same model tier as query correction.
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
    'query_best_practices',
    'Query Best Practices Agent',
    'gemini/gemini-3.1-flash-lite-preview',
    1024,
    0.2,
    20,
    true
) ON CONFLICT (agent_id) DO NOTHING;
