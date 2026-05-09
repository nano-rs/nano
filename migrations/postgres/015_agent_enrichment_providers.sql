-- Agent Enrichment Providers Table
-- Stores configuration for AI-powered enrichment providers (VirusTotal, AbuseIPDB, etc.)
-- Used by the AI Alert Agent for automated alert triage and enrichment

CREATE TABLE IF NOT EXISTS agent_enrichment_providers (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,  -- 'virustotal', 'abuseipdb', 'shodan', 'greynoise', etc.
    enabled BOOLEAN DEFAULT false,
    api_key_encrypted BYTEA,  -- AES-256-GCM encrypted API key
    config JSONB DEFAULT '{}',  -- Provider-specific configuration
    rate_limit_per_minute INTEGER DEFAULT 4,
    rate_limit_per_day INTEGER DEFAULT 500,
    requests_today INTEGER DEFAULT 0,
    last_request_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Trigger to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_agent_enrichment_providers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_agent_enrichment_providers_updated_at
    BEFORE UPDATE ON agent_enrichment_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_agent_enrichment_providers_updated_at();

-- Index for efficient lookups by provider type
CREATE INDEX IF NOT EXISTS idx_agent_enrichment_providers_type 
ON agent_enrichment_providers(provider_type);

-- Index for finding enabled providers
CREATE INDEX IF NOT EXISTS idx_agent_enrichment_providers_enabled 
ON agent_enrichment_providers(enabled) 
WHERE enabled = true;

-- Comments for documentation
COMMENT ON TABLE agent_enrichment_providers IS 'Configuration for AI-powered enrichment providers used in alert triage';
COMMENT ON COLUMN agent_enrichment_providers.id IS 'Unique provider identifier (e.g., virustotal, abuseipdb)';
COMMENT ON COLUMN agent_enrichment_providers.provider_type IS 'Type of provider for grouping (e.g., threat_intel, reputation)';
COMMENT ON COLUMN agent_enrichment_providers.api_key_encrypted IS 'AES-256-GCM encrypted API key for the provider';
COMMENT ON COLUMN agent_enrichment_providers.config IS 'Provider-specific configuration as JSON';
COMMENT ON COLUMN agent_enrichment_providers.rate_limit_per_minute IS 'Maximum API requests per minute';
COMMENT ON COLUMN agent_enrichment_providers.rate_limit_per_day IS 'Maximum API requests per day';
COMMENT ON COLUMN agent_enrichment_providers.requests_today IS 'Counter for requests made today (reset daily)';
