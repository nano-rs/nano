-- Log Sources - Unified entity merging feeds and parsers
-- Combines ingestion configuration, VRL transformation, and metadata into a single entity

-- Create log_sources table
CREATE TABLE IF NOT EXISTS log_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,

    -- Ingestion Configuration (from parsers)
    source_type VARCHAR(100) NOT NULL,              -- 'routed', 'file', 'syslog', 'http', 'kafka', 'aws_s3', 'azure_blob'
    source_config JSONB NOT NULL DEFAULT '{}',      -- Source-specific configuration
    credential_id UUID REFERENCES cloud_credentials(id) ON DELETE SET NULL,

    -- Transformation (from parsers)
    parser_vrl TEXT NOT NULL,                       -- VRL code for parsing/transformation
    output_fields JSONB,                            -- Expected output field mappings

    -- Metadata (from feeds)
    category VARCHAR(100),                          -- 'network', 'endpoint', 'cloud', 'application', 'security', 'system', 'identity'
    vendor VARCHAR(255),                            -- e.g., 'Cisco', 'Palo Alto', 'AWS', 'Microsoft'
    product VARCHAR(255),                           -- e.g., 'ASA', 'Firewall', 'CloudTrail', 'Windows'
    icon VARCHAR(50),                               -- Icon name for UI
    color VARCHAR(20),                              -- Color for UI badges

    -- Matching criteria (from feeds - for routing/discovery)
    match_field VARCHAR(255),                       -- Field to match on (e.g., 'metadata.source', 'source_type')
    match_pattern VARCHAR(512),                     -- Regex pattern to match
    match_values TEXT[],                            -- Exact values to match (alternative to pattern)

    -- Validation & Deployment Status
    validated BOOLEAN NOT NULL DEFAULT false,
    validation_error TEXT,
    deployed BOOLEAN NOT NULL DEFAULT false,
    deployed_at TIMESTAMPTZ,

    -- Status
    enabled BOOLEAN NOT NULL DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_log_sources_enabled ON log_sources (enabled);
CREATE INDEX IF NOT EXISTS idx_log_sources_deployed ON log_sources (deployed);
CREATE INDEX IF NOT EXISTS idx_log_sources_source_type ON log_sources (source_type);
CREATE INDEX IF NOT EXISTS idx_log_sources_category ON log_sources (category);
CREATE INDEX IF NOT EXISTS idx_log_sources_vendor ON log_sources (vendor);
CREATE INDEX IF NOT EXISTS idx_log_sources_name ON log_sources (name);
CREATE INDEX IF NOT EXISTS idx_log_sources_credential_id ON log_sources (credential_id) WHERE credential_id IS NOT NULL;

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_log_sources_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS log_sources_updated_at ON log_sources;
CREATE TRIGGER log_sources_updated_at
    BEFORE UPDATE ON log_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_log_sources_updated_at();

-- Migrate data: Parsers WITH feed_id (linked to feeds)
INSERT INTO log_sources (
    id, name, description,
    source_type, source_config, credential_id,
    parser_vrl, output_fields,
    category, vendor, product, icon, color,
    match_field, match_pattern, match_values,
    validated, validation_error, deployed, enabled,
    created_at, updated_at
)
SELECT
    p.id,
    p.name,
    COALESCE(p.description, f.description),
    p.source_type,
    p.source_config,
    p.credential_id,
    p.parser_vrl,
    p.output_fields,
    f.category,
    f.vendor,
    f.product,
    f.icon,
    f.color,
    f.match_field,
    f.match_pattern,
    f.match_values,
    p.validated,
    p.validation_error,
    p.enabled,  -- deployed = was enabled
    p.enabled,
    p.created_at,
    GREATEST(p.updated_at, f.updated_at)
FROM parsers p
JOIN feeds f ON p.feed_id = f.id;

-- Migrate data: Orphan parsers (no feed_id) as standalone log sources
INSERT INTO log_sources (
    id, name, description,
    source_type, source_config, credential_id,
    parser_vrl, output_fields,
    validated, validation_error, deployed, enabled,
    created_at, updated_at
)
SELECT
    p.id,
    p.name,
    p.description,
    p.source_type,
    p.source_config,
    p.credential_id,
    p.parser_vrl,
    p.output_fields,
    p.validated,
    p.validation_error,
    p.enabled,
    p.enabled,
    p.created_at,
    p.updated_at
FROM parsers p
WHERE p.feed_id IS NULL
ON CONFLICT (name) DO NOTHING;

-- Migrate data: Feeds without parsers (become log sources with placeholder VRL)
INSERT INTO log_sources (
    name, description,
    source_type, source_config,
    parser_vrl,
    category, vendor, product, icon, color,
    match_field, match_pattern, match_values,
    validated, enabled,
    created_at, updated_at
)
SELECT
    f.name,
    f.description,
    'routed',  -- default source type
    '{}'::jsonb,
    E'# Auto-migrated from feed: ' || f.name || E'\n' ||
    E'# TODO: Configure VRL parser\n' ||
    E'.source_type = "' || f.name || E'"\n' ||
    E'.udm.timestamp = to_string(now())\n' ||
    E'.message = string!(.message)\n',
    f.category,
    f.vendor,
    f.product,
    f.icon,
    f.color,
    f.match_field,
    f.match_pattern,
    f.match_values,
    false,  -- not validated
    false,  -- not enabled
    f.created_at,
    f.updated_at
FROM feeds f
WHERE NOT EXISTS (SELECT 1 FROM parsers p WHERE p.feed_id = f.id)
ON CONFLICT (name) DO NOTHING;

-- Rename parser_deployments to log_source_deployments (if it exists)
ALTER TABLE IF EXISTS parser_deployments RENAME TO log_source_deployments;
ALTER TABLE IF EXISTS log_source_deployments RENAME COLUMN parser_id TO log_source_id;

-- Create log_source_deployments if it doesn't exist (handles fresh installs)
CREATE TABLE IF NOT EXISTS log_source_deployments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    log_source_id UUID NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,          -- 'deploy', 'undeploy', 'rollback'
    status VARCHAR(50) NOT NULL,          -- 'success', 'failed', 'rolled_back'
    error_message TEXT,
    config_snapshot TEXT,                 -- Optional snapshot of the deployed config
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Drop old foreign key if it exists (from renamed table)
ALTER TABLE log_source_deployments DROP CONSTRAINT IF EXISTS parser_deployments_parser_id_fkey;

-- Ensure foreign key exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'log_source_deployments_log_source_id_fkey'
    ) THEN
        ALTER TABLE log_source_deployments
            ADD CONSTRAINT log_source_deployments_log_source_id_fkey
            FOREIGN KEY (log_source_id) REFERENCES log_sources(id) ON DELETE CASCADE;
    END IF;
END $$;

-- Update indexes
DROP INDEX IF EXISTS idx_parser_deployments_parser_id;
CREATE INDEX IF NOT EXISTS idx_log_source_deployments_log_source_id ON log_source_deployments(log_source_id);
CREATE INDEX IF NOT EXISTS idx_log_source_deployments_deployed_at ON log_source_deployments(deployed_at DESC);

-- Add permissions for log sources
INSERT INTO permissions (id, name, description, category) VALUES
    ('log_sources:view', 'View Log Sources', 'View log source configurations', 'log_sources'),
    ('log_sources:create', 'Create Log Sources', 'Create new log sources', 'log_sources'),
    ('log_sources:edit', 'Edit Log Sources', 'Modify log source configurations', 'log_sources'),
    ('log_sources:delete', 'Delete Log Sources', 'Remove log sources', 'log_sources'),
    ('log_sources:deploy', 'Deploy Log Sources', 'Deploy log sources to Vector', 'log_sources')
ON CONFLICT (id) DO NOTHING;

-- Grant all log source permissions to Admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.id = '00000000-0000-0000-0000-000000000001'  -- Admin role UUID
  AND p.id IN ('log_sources:view', 'log_sources:create', 'log_sources:edit', 'log_sources:delete', 'log_sources:deploy')
ON CONFLICT DO NOTHING;

-- Grant view/edit/deploy permissions to Editor role
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002'::uuid, p.id
FROM permissions p
WHERE p.id IN ('log_sources:view', 'log_sources:edit', 'log_sources:deploy')
ON CONFLICT DO NOTHING;

-- Grant view permission to Analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid, p.id
FROM permissions p
WHERE p.id = 'log_sources:view'
ON CONFLICT DO NOTHING;

-- Comments
COMMENT ON TABLE log_sources IS 'Unified log source configuration combining ingestion, transformation, and metadata';
COMMENT ON COLUMN log_sources.source_type IS 'Ingestion method: routed, file, syslog, http, kafka, aws_s3, azure_blob';
COMMENT ON COLUMN log_sources.source_config IS 'Source-specific configuration (paths, addresses, credentials, etc.)';
COMMENT ON COLUMN log_sources.parser_vrl IS 'VRL code for parsing and transforming logs';
COMMENT ON COLUMN log_sources.category IS 'Log category: network, endpoint, cloud, application, security, system, identity';
COMMENT ON COLUMN log_sources.match_field IS 'Field to match on for routing (e.g., metadata.source_type)';
COMMENT ON COLUMN log_sources.deployed IS 'Whether the log source is currently deployed to Vector';
