-- ============================================================================
-- Migration 054: Namespaces for Network Context Isolation
-- ============================================================================
-- Creates namespaces table and adds namespace support to log_sources.
-- This enables identity resolution to work correctly with overlapping
-- private IP address spaces (multi-cloud, VPCs, on-prem).
--
-- Namespace format: {provider}:{account/project}:{network}
-- Examples:
--   - aws:123456789012:vpc-abc123
--   - gcp:my-project:vpc-prod
--   - azure:sub-xxx:vnet-corp
--   - onprem:dc-east:vlan100
--   - default (fallback)
-- ============================================================================

-- Create namespaces table
CREATE TABLE IF NOT EXISTS namespaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    provider VARCHAR(50),  -- aws, gcp, azure, onprem, etc.
    account_id VARCHAR(255),  -- AWS account, GCP project, Azure subscription
    network_id VARCHAR(255),  -- VPC ID, VNet ID, VLAN, etc.
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default namespace
INSERT INTO namespaces (id, name, description, provider)
VALUES ('00000000-0000-0000-0000-000000000000', 'default', 'Default namespace for unscoped resources', 'default')
ON CONFLICT (name) DO NOTHING;

-- Add index for provider lookups
CREATE INDEX IF NOT EXISTS idx_namespaces_provider ON namespaces(provider);

-- Comment for documentation
COMMENT ON TABLE namespaces IS 'Network namespaces for identity resolution isolation across overlapping IP spaces';

-- Add namespace column to log_sources (legacy VARCHAR for backwards compat)
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS namespace VARCHAR(255) DEFAULT 'default';

-- Add namespace_id foreign key to log_sources
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS namespace_id UUID REFERENCES namespaces(id) DEFAULT '00000000-0000-0000-0000-000000000000';

-- Add index for filtering by namespace
CREATE INDEX IF NOT EXISTS idx_log_sources_namespace ON log_sources(namespace);
CREATE INDEX IF NOT EXISTS idx_log_sources_namespace_id ON log_sources(namespace_id);

-- Comment for documentation
COMMENT ON COLUMN log_sources.namespace IS 'Network namespace name for identity resolution (legacy, use namespace_id)';
COMMENT ON COLUMN log_sources.namespace_id IS 'Reference to namespaces table for network isolation';
