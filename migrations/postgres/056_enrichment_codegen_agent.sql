-- ============================================================================
-- Migration 056: Add Enrichment Code Generator Agent Config
-- ============================================================================
-- Adds configuration for the AI agent that generates custom enrichment code.
-- This allows selecting which model to use for code generation via the
-- MeloD AI Settings UI.
-- ============================================================================

-- Add the enrichment_codegen agent to the config table
INSERT INTO agent_model_config (
    agent_id,
    display_name,
    model_id,
    max_tokens,
    temperature,
    timeout_seconds,
    enabled
) VALUES (
    'enrichment_codegen',
    'Enrichment Code Generator',
    'anthropic/claude-sonnet-4-5',
    8192,
    0.7,
    120,
    true
) ON CONFLICT (agent_id) DO NOTHING;
