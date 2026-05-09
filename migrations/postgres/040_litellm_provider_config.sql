-- LiteLLM provider configuration tables for multi-provider AI support
-- Enables dynamic model configuration without service restarts

-- Provider credentials table - stores encrypted API keys for each AI provider
CREATE TABLE IF NOT EXISTS provider_credentials (
    provider TEXT PRIMARY KEY,  -- 'anthropic', 'google', 'openai', 'azure', 'bedrock'
    display_name TEXT NOT NULL,
    credentials_encrypted BYTEA,  -- AES-256-GCM encrypted API keys (JSONB)
    config JSONB DEFAULT '{}',    -- Provider-specific config (region, endpoint, etc.)
    enabled BOOLEAN DEFAULT false,
    last_validated_at TIMESTAMPTZ,
    validation_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed provider entries (credentials added via UI)
INSERT INTO provider_credentials (provider, display_name, config, enabled) VALUES
    ('anthropic', 'Anthropic', '{}', false),
    ('google', 'Google AI', '{}', false),
    ('openai', 'OpenAI', '{}', false),
    ('azure', 'Azure OpenAI', '{"api_version": "2024-10-21"}', false),
    ('bedrock', 'AWS Bedrock', '{"region": "us-east-1"}', false)
ON CONFLICT (provider) DO NOTHING;

-- Agent model configuration - per-agent model assignments
CREATE TABLE IF NOT EXISTS agent_model_config (
    agent_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    model_id TEXT NOT NULL DEFAULT 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0',
    max_tokens INTEGER DEFAULT 4096,
    temperature REAL DEFAULT 0.7,
    timeout_seconds INTEGER DEFAULT 120,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Available models reference table - catalog of supported models
CREATE TABLE IF NOT EXISTS available_models (
    model_id TEXT PRIMARY KEY,           -- e.g., 'anthropic/claude-sonnet-4-5'
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    context_window INTEGER,
    input_price_per_million REAL,
    output_price_per_million REAL,
    supports_vision BOOLEAN DEFAULT false,
    supports_function_calling BOOLEAN DEFAULT true,
    deprecated BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default agent configurations for all 15 agents
INSERT INTO agent_model_config (agent_id, display_name, model_id, max_tokens, temperature, timeout_seconds) VALUES
    -- Core agents
    ('query', 'Query Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 8192, 0.7, 120),
    ('detection', 'Detection Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 16384, 0.7, 180),
    ('parser', 'Parser Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 16384, 0.7, 180),
    ('parser_edit', 'Parser Edit Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 8192, 0.7, 120),
    ('summarize', 'Summarize Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 65536, 0.7, 120),
    ('dashboard', 'Dashboard Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 16384, 0.7, 180),
    ('timeline', 'Timeline Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 32768, 0.7, 180),
    -- Alert triage agents
    ('triage_initial', 'Initial Triage Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 4096, 0.7, 60),
    ('triage_correlation', 'Correlation Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 131072, 0.7, 120),
    ('triage_enrichment', 'Enrichment Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 4096, 0.7, 60),
    ('triage_context', 'Context Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 131072, 0.7, 120),
    ('triage_risk', 'Risk Assessment Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 4096, 0.7, 60),
    ('triage_verdict', 'Verdict Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 8192, 0.7, 120),
    -- Tuning agents
    ('tuning_auto', 'Auto-Tuner Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 8192, 0.7, 120),
    ('tuning_hint', 'Hint Proposal Agent', 'bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 4096, 0.7, 60)
ON CONFLICT (agent_id) DO NOTHING;

-- Insert available models catalog
INSERT INTO available_models (model_id, provider, display_name, context_window, input_price_per_million, output_price_per_million, supports_vision, supports_function_calling) VALUES
    -- Anthropic (Direct API)
    ('anthropic/claude-opus-4-5', 'anthropic', 'Claude Opus 4.5', 200000, 15.00, 75.00, true, true),
    ('anthropic/claude-sonnet-4-5', 'anthropic', 'Claude Sonnet 4.5', 200000, 3.00, 15.00, true, true),
    ('anthropic/claude-sonnet-4', 'anthropic', 'Claude Sonnet 4', 200000, 3.00, 15.00, true, true),
    ('anthropic/claude-haiku-4-5', 'anthropic', 'Claude Haiku 4.5', 200000, 1.00, 5.00, true, true),
    ('anthropic/claude-3-5-sonnet', 'anthropic', 'Claude 3.5 Sonnet', 200000, 3.00, 15.00, true, true),
    ('anthropic/claude-3-5-haiku', 'anthropic', 'Claude 3.5 Haiku', 200000, 0.25, 1.25, false, true),
    -- AWS Bedrock (Anthropic models)
    ('bedrock/us.anthropic.claude-opus-4-5-20251101-v1:0', 'bedrock', 'Claude Opus 4.5 (Bedrock)', 200000, NULL, NULL, true, true),
    ('bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0', 'bedrock', 'Claude Sonnet 4.5 (Bedrock)', 200000, NULL, NULL, true, true),
    ('bedrock/us.anthropic.claude-sonnet-4-20250514-v1:0', 'bedrock', 'Claude Sonnet 4 (Bedrock)', 200000, NULL, NULL, true, true),
    ('bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0', 'bedrock', 'Claude Haiku 4.5 (Bedrock)', 200000, NULL, NULL, true, true),
    ('bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0', 'bedrock', 'Claude 3.5 Sonnet v2 (Bedrock)', 200000, NULL, NULL, true, true),
    ('bedrock/anthropic.claude-3-5-haiku-20241022-v1:0', 'bedrock', 'Claude 3.5 Haiku (Bedrock)', 200000, NULL, NULL, false, true),
    -- Google Gemini
    ('gemini/gemini-3-pro-preview', 'google', 'Gemini 3 Pro', 1000000, 1.25, 5.00, true, true),
    ('gemini/gemini-3-flash-preview', 'google', 'Gemini 3 Flash', 1000000, 0.075, 0.30, true, true),
    ('gemini/gemini-2.5-pro', 'google', 'Gemini 2.5 Pro', 1000000, 1.25, 5.00, true, true),
    ('gemini/gemini-2.5-flash', 'google', 'Gemini 2.5 Flash', 1000000, 0.075, 0.30, true, true),
    ('gemini/gemini-2.5-flash-lite', 'google', 'Gemini 2.5 Flash-Lite', 1000000, 0.02, 0.08, true, true),
    -- OpenAI
    ('openai/gpt-5.2', 'openai', 'GPT-5.2', 1000000, 5.00, 15.00, true, true),
    ('openai/gpt-5-mini', 'openai', 'GPT-5 Mini', 1000000, 0.40, 1.60, true, true),
    ('openai/gpt-5-nano', 'openai', 'GPT-5 Nano', 1000000, 0.10, 0.40, false, true),
    ('openai/gpt-4.1', 'openai', 'GPT-4.1 (Legacy)', 1000000, 2.00, 8.00, true, true),
    ('openai/o4-mini', 'openai', 'o4-mini (Reasoning)', 128000, 1.10, 4.40, true, true),
    -- Azure OpenAI
    ('azure/gpt-5.2', 'azure', 'GPT-5.2 (Azure)', 1000000, NULL, NULL, true, true),
    ('azure/gpt-5-mini', 'azure', 'GPT-5 Mini (Azure)', 1000000, NULL, NULL, true, true),
    ('azure/gpt-5-nano', 'azure', 'GPT-5 Nano (Azure)', 1000000, NULL, NULL, false, true),
    ('azure/o4-mini', 'azure', 'o4-mini (Azure)', 128000, NULL, NULL, true, true)
ON CONFLICT (model_id) DO NOTHING;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_provider_credentials_enabled ON provider_credentials(enabled);
CREATE INDEX IF NOT EXISTS idx_agent_model_config_enabled ON agent_model_config(enabled);
CREATE INDEX IF NOT EXISTS idx_available_models_provider ON available_models(provider);
CREATE INDEX IF NOT EXISTS idx_available_models_deprecated ON available_models(deprecated);

-- Add permissions for LiteLLM settings management
INSERT INTO permissions (id, name, description, category) VALUES
    ('settings:ai_providers', 'settings:ai_providers', 'Manage AI provider credentials', 'settings'),
    ('settings:agent_models', 'settings:agent_models', 'Configure per-agent model assignments', 'settings')
ON CONFLICT (id) DO NOTHING;

-- Grant new permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name IN ('settings:ai_providers', 'settings:agent_models')
ON CONFLICT (role_id, permission_id) DO NOTHING;
