-- Source Configurations - Separate infrastructure (connection + routing) from parsing
-- This enables multiple log types from a single connection (e.g., one SQS queue serving multiple S3 buckets)

-- Create source_configurations table
CREATE TABLE IF NOT EXISTS source_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,

    -- Configuration type
    config_type VARCHAR(50) NOT NULL,  -- 'http', 'kafka', 'aws_s3', 'gcp_pubsub', 'splunk_hec', 'vector'

    -- Connection configuration (type-specific JSON)
    connection_config JSONB NOT NULL DEFAULT '{}',

    -- Credential reference (for cloud providers)
    credential_id UUID REFERENCES cloud_credentials(id) ON DELETE SET NULL,

    -- Status
    enabled BOOLEAN NOT NULL DEFAULT false,
    deployed BOOLEAN NOT NULL DEFAULT false,
    deployed_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create routing_rules table
CREATE TABLE IF NOT EXISTS routing_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Parent reference
    source_configuration_id UUID NOT NULL REFERENCES source_configurations(id) ON DELETE CASCADE,

    -- Rule priority (lower = higher priority, 0 = default fallback)
    priority INT NOT NULL DEFAULT 100,

    -- Matching criteria
    match_field VARCHAR(255) NOT NULL,        -- 'bucket', 'topic', 'sourcetype', 'key', etc.
    match_type VARCHAR(50) NOT NULL,          -- 'exact', 'prefix', 'suffix', 'regex', 'contains', 'default'
    match_value VARCHAR(512),                 -- NULL for 'default' type

    -- Target source type (what LogSource/parser handles this)
    target_source_type VARCHAR(255) NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Each source config can only have one rule at each priority level
    UNIQUE(source_configuration_id, priority)
);

-- Indexes for source_configurations
CREATE INDEX IF NOT EXISTS idx_source_configurations_enabled ON source_configurations(enabled);
CREATE INDEX IF NOT EXISTS idx_source_configurations_deployed ON source_configurations(deployed);
CREATE INDEX IF NOT EXISTS idx_source_configurations_config_type ON source_configurations(config_type);
CREATE INDEX IF NOT EXISTS idx_source_configurations_name ON source_configurations(name);
CREATE INDEX IF NOT EXISTS idx_source_configurations_credential_id ON source_configurations(credential_id) WHERE credential_id IS NOT NULL;

-- Indexes for routing_rules
CREATE INDEX IF NOT EXISTS idx_routing_rules_source_config ON routing_rules(source_configuration_id);
CREATE INDEX IF NOT EXISTS idx_routing_rules_priority ON routing_rules(source_configuration_id, priority);
CREATE INDEX IF NOT EXISTS idx_routing_rules_target ON routing_rules(target_source_type);

-- Trigger for source_configurations updated_at
CREATE OR REPLACE FUNCTION update_source_configurations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS source_configurations_updated_at ON source_configurations;
CREATE TRIGGER source_configurations_updated_at
    BEFORE UPDATE ON source_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_source_configurations_updated_at();

-- Add permissions for source configurations
INSERT INTO permissions (id, name, description, category) VALUES
    ('source_configs:view', 'View Source Configurations', 'View source configuration settings', 'source_configs'),
    ('source_configs:create', 'Create Source Configurations', 'Create new source configurations', 'source_configs'),
    ('source_configs:edit', 'Edit Source Configurations', 'Modify source configuration settings', 'source_configs'),
    ('source_configs:delete', 'Delete Source Configurations', 'Remove source configurations', 'source_configs'),
    ('source_configs:deploy', 'Deploy Source Configurations', 'Deploy source configurations to Vector', 'source_configs')
ON CONFLICT (id) DO NOTHING;

-- Grant all source config permissions to Admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.id = '00000000-0000-0000-0000-000000000001'  -- Admin role UUID
  AND p.id IN ('source_configs:view', 'source_configs:create', 'source_configs:edit', 'source_configs:delete', 'source_configs:deploy')
ON CONFLICT DO NOTHING;

-- Grant view/edit/deploy permissions to Editor role
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002'::uuid, p.id
FROM permissions p
WHERE p.id IN ('source_configs:view', 'source_configs:edit', 'source_configs:deploy')
ON CONFLICT DO NOTHING;

-- Grant view permission to Analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid, p.id
FROM permissions p
WHERE p.id = 'source_configs:view'
ON CONFLICT DO NOTHING;

-- Create source_configuration_deployments table for deployment history
CREATE TABLE IF NOT EXISTS source_configuration_deployments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_configuration_id UUID NOT NULL REFERENCES source_configurations(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,          -- 'deploy', 'undeploy', 'rollback'
    status VARCHAR(50) NOT NULL,          -- 'success', 'failed', 'rolled_back'
    error_message TEXT,
    config_snapshot TEXT,                 -- Optional snapshot of the deployed config
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_source_config_deployments_source_config
    ON source_configuration_deployments(source_configuration_id);
CREATE INDEX IF NOT EXISTS idx_source_config_deployments_deployed_at
    ON source_configuration_deployments(deployed_at DESC);

-- Comments
COMMENT ON TABLE source_configurations IS 'Infrastructure configurations for log ingestion (Kafka, S3, etc.)';
COMMENT ON COLUMN source_configurations.config_type IS 'Type of source: http, kafka, aws_s3, gcp_pubsub, splunk_hec, vector';
COMMENT ON COLUMN source_configurations.connection_config IS 'Type-specific connection settings (bootstrap servers, SQS URL, etc.)';
COMMENT ON TABLE routing_rules IS 'Rules that determine source_type based on message attributes';
COMMENT ON COLUMN routing_rules.match_field IS 'Field to match on: bucket, topic, sourcetype, key, etc.';
COMMENT ON COLUMN routing_rules.match_type IS 'Match method: exact, prefix, suffix, regex, contains, default';
COMMENT ON COLUMN routing_rules.target_source_type IS 'The source_type value that activates a LogSource parser';

-- ============================================================================
-- SEED SOURCE CONFIGURATIONS
-- System-level source configurations for HTTP and Vector ingestion
-- ============================================================================

-- HTTP Ingestion (system-level, always enabled)
-- Corresponds to 00-base.toml - receives logs via HTTP POST with X-Source-Type header
INSERT INTO source_configurations (
    id, name, description, config_type, connection_config, enabled, deployed, deployed_at
) VALUES (
    '30000000-0000-0000-0000-000000000001',
    'HTTP Ingestion',
    'Receives events via HTTP POST with X-Source-Type header. System-level source always enabled.',
    'http',
    '{"address": "0.0.0.0:8080", "path": "/ingest", "auth": "token"}'::jsonb,
    true,
    true,
    NOW()
) ON CONFLICT (name) DO NOTHING;

-- Vector Ingestion (system-level)
-- Corresponds to 01-vector-source.toml - receives from upstream Vector instances
INSERT INTO source_configurations (
    id, name, description, config_type, connection_config, enabled, deployed, deployed_at
) VALUES (
    '30000000-0000-0000-0000-000000000002',
    'Vector Ingestion',
    'Receives events from upstream Vector instances (aggregators, forwarders). Port 6000 is the standard Vector-to-Vector port.',
    'vector',
    '{"address": "0.0.0.0:6000", "version": "2", "acknowledgements": true}'::jsonb,
    true,
    true,
    NOW()
) ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- SEED ROUTING RULES
-- Default routing rules for HTTP ingestion based on X-Source-Type header
-- ============================================================================

-- HTTP Ingestion routing rules (match source_type from X-Source-Type header)
INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type)
SELECT '30000000-0000-0000-0000-000000000001'::uuid, priority, 'source_type', match_type, match_value, target_source_type
FROM (VALUES
    -- Apache
    (10, 'exact', 'apache', 'apache'),
    (11, 'exact', 'apache_access', 'apache'),
    (12, 'exact', 'apache_error', 'apache'),
    -- Json Generic
    (20, 'exact', 'json', 'json_generic'),
    (21, 'exact', 'json_generic', 'json_generic'),
    -- Squid Proxy
    (30, 'exact', 'squid', 'squid_proxy'),
    (31, 'exact', 'squid_proxy', 'squid_proxy'),
    -- Sysmon
    (40, 'exact', 'sysmon', 'sysmon'),
    (41, 'exact', 'windows_sysmon', 'sysmon'),
    -- Default fallback
    (1000, 'default', NULL, 'unknown')
) AS rules(priority, match_type, match_value, target_source_type)
WHERE EXISTS (SELECT 1 FROM source_configurations WHERE id = '30000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

-- Vector Ingestion routing rule (passthrough - uses source_type from upstream)
INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type)
SELECT '30000000-0000-0000-0000-000000000002'::uuid, 1000, 'source_type', 'default', NULL, '${source_type}'
WHERE EXISTS (SELECT 1 FROM source_configurations WHERE id = '30000000-0000-0000-0000-000000000002')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- SEED ADDITIONAL SOURCE CONFIGURATIONS (disabled templates)
-- These are pre-configured but disabled - users just need to add credentials and enable
-- ============================================================================

-- Kafka (disabled template)
INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed)
VALUES (
    '30000000-0000-0000-0000-000000000003',
    'Kafka',
    'Consume logs from Apache Kafka topics. Configure bootstrap servers and topics, then add routing rules based on topic names.',
    'kafka',
    '{"bootstrap_servers": "", "topics": [], "group_id": "nanosiem", "auto_offset_reset": "latest"}'::jsonb,
    false,
    false
) ON CONFLICT (name) DO NOTHING;

-- AWS S3 (disabled template)
INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed)
VALUES (
    '30000000-0000-0000-0000-000000000004',
    'AWS S3',
    'Ingest logs from AWS S3 via SQS notifications. Configure your SQS queue URL and add routing rules based on bucket or key patterns.',
    'aws_s3',
    '{"sqs_queue_url": "", "region": "us-east-1", "compression": "auto"}'::jsonb,
    false,
    false
) ON CONFLICT (name) DO NOTHING;

-- GCP Pub/Sub (disabled template)
INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed)
VALUES (
    '30000000-0000-0000-0000-000000000005',
    'GCP Pub/Sub',
    'Subscribe to Google Cloud Pub/Sub topics. Configure your project and subscription, then add routing rules based on message attributes.',
    'gcp_pubsub',
    '{"project": "", "subscription": "", "ack_deadline_secs": 60}'::jsonb,
    false,
    false
) ON CONFLICT (name) DO NOTHING;

-- Splunk HEC (disabled template)
INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed)
VALUES (
    '30000000-0000-0000-0000-000000000006',
    'Splunk HEC',
    'Receive logs via Splunk HTTP Event Collector protocol. Configure tokens and add routing rules based on sourcetype.',
    'splunk_hec',
    '{"address": "0.0.0.0:8088", "valid_tokens": []}'::jsonb,
    false,
    false
) ON CONFLICT (name) DO NOTHING;
