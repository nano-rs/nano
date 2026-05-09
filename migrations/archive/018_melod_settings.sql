-- meloD AI Settings Schema
-- Migration: 018_melod_settings.sql
--
-- Stores meloD AI configuration including:
-- - AWS Bedrock connection settings
-- - Model configuration
-- - Rate limiting parameters
-- - Encrypted credentials
-- - Connection status tracking

-- ============================================================================
-- meloD Settings Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS melod_settings (
    id TEXT PRIMARY KEY DEFAULT 'default',  -- Single row, keyed as 'default'
    
    -- Feature toggle
    enabled BOOLEAN NOT NULL DEFAULT false,
    
    -- Provider configuration
    provider TEXT NOT NULL DEFAULT 'aws_bedrock',
    
    -- AWS Bedrock configuration (stored as JSONB)
    config JSONB NOT NULL DEFAULT '{
        "aws_region": "us-east-1",
        "model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "max_tokens": 4096,
        "temperature": 0.7,
        "requests_per_minute": 60
    }'::jsonb,
    
    -- Encrypted credentials (stored as JSONB with encrypted values)
    -- The actual values are encrypted using AES-256-GCM
    credentials_encrypted JSONB DEFAULT NULL,
    
    -- Connection status tracking
    connection_status JSONB NOT NULL DEFAULT '{
        "connected": false,
        "model_available": false,
        "last_checked": null,
        "error": null
    }'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure only one settings row exists
CREATE UNIQUE INDEX IF NOT EXISTS idx_melod_settings_singleton ON melod_settings ((id = 'default'));

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_melod_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS melod_settings_updated_at ON melod_settings;
CREATE TRIGGER melod_settings_updated_at
    BEFORE UPDATE ON melod_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_melod_settings_updated_at();

-- Insert default settings row
INSERT INTO melod_settings (id) VALUES ('default')
ON CONFLICT (id) DO NOTHING;
