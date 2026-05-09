-- ============================================================================
-- Migration 055: Custom Enrichments
-- ============================================================================
-- Adds tables for user-defined custom enrichments that can fetch data from
-- arbitrary APIs. Supports two types:
--   - Data: Bulk data fetched on schedule (e.g., threat intel feeds)
--   - Agent: On-demand lookups for specific artifacts (IPs, domains, hashes)
--
-- Custom enrichment code runs in a Deno sandbox with restricted permissions.
-- ============================================================================

-- Custom enrichment definitions
CREATE TABLE custom_enrichments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID NOT NULL REFERENCES namespaces(id),

    -- Identity
    name VARCHAR(100) NOT NULL,
    description TEXT,
    enrichment_type VARCHAR(20) NOT NULL CHECK (enrichment_type IN ('data', 'agent')),

    -- Code storage
    code TEXT NOT NULL,
    code_language VARCHAR(20) DEFAULT 'typescript',  -- typescript for Deno
    code_version INT DEFAULT 1,

    -- Configuration
    config JSONB DEFAULT '{}',  -- type-specific config
    -- Data type: { key_field, key_type, source_url, refresh_schedule, watermark_field }
    -- Agent type: { artifact_types, trigger, rate_limit_per_min, rate_limit_per_day }

    -- Credentials (reference, not stored here)
    credential_id UUID REFERENCES cloud_credentials(id),
    allowed_domains TEXT[] DEFAULT '{}',  -- Network allowlist for sandbox

    -- Status
    enabled BOOLEAN DEFAULT false,
    status VARCHAR(20) DEFAULT 'draft',  -- draft, validating, active, failed
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(20),
    last_error TEXT,

    -- Audit
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(namespace_id, name)
);

-- Code version history
CREATE TABLE custom_enrichment_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enrichment_id UUID NOT NULL REFERENCES custom_enrichments(id) ON DELETE CASCADE,
    version INT NOT NULL,
    code TEXT NOT NULL,
    config JSONB,
    change_summary TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(enrichment_id, version)
);

-- Validation/test runs
CREATE TABLE custom_enrichment_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enrichment_id UUID NOT NULL REFERENCES custom_enrichments(id) ON DELETE CASCADE,
    run_type VARCHAR(20) NOT NULL,  -- 'validation', 'scheduled', 'manual'
    status VARCHAR(20) NOT NULL,     -- 'running', 'success', 'failed'
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    records_fetched INT,
    records_stored INT,
    error_message TEXT,
    error_details JSONB,
    sample_output JSONB,  -- First few records for preview
    created_by UUID REFERENCES users(id)
);

-- Indexes for efficient queries
CREATE INDEX idx_ce_namespace ON custom_enrichments(namespace_id);
CREATE INDEX idx_ce_type ON custom_enrichments(enrichment_type);
CREATE INDEX idx_ce_enabled ON custom_enrichments(enabled) WHERE enabled = true;
CREATE INDEX idx_ce_status ON custom_enrichments(status);
CREATE INDEX idx_cev_enrichment ON custom_enrichment_versions(enrichment_id);
CREATE INDEX idx_cer_enrichment ON custom_enrichment_runs(enrichment_id);
CREATE INDEX idx_cer_status ON custom_enrichment_runs(status) WHERE status = 'running';

-- Comments for documentation
COMMENT ON TABLE custom_enrichments IS 'User-defined custom enrichments with TypeScript code running in Deno sandbox';
COMMENT ON COLUMN custom_enrichments.enrichment_type IS 'data = bulk scheduled fetch, agent = on-demand artifact lookup';
COMMENT ON COLUMN custom_enrichments.config IS 'Type-specific configuration (schedule, triggers, rate limits)';
COMMENT ON COLUMN custom_enrichments.allowed_domains IS 'Network allowlist for sandbox (e.g., api.example.com)';
COMMENT ON TABLE custom_enrichment_versions IS 'Version history for custom enrichment code changes';
COMMENT ON TABLE custom_enrichment_runs IS 'Execution history for validation and scheduled runs';

-- ============================================================================
-- PERMISSIONS: Add custom enrichment permissions
-- ============================================================================
INSERT INTO permissions (id, name, description, category) VALUES
    ('enrichments:code', 'Edit Enrichment Code', 'Access the manual code editor for enrichments', 'enrichments'),
    ('enrichments:custom:create', 'Create Custom Enrichments', 'Create and edit custom enrichments with AI code generation', 'enrichments'),
    ('enrichments:custom:delete', 'Delete Custom Enrichments', 'Delete custom enrichments', 'enrichments')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ADMIN ROLE: Grant all custom enrichment permissions
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id
FROM permissions
WHERE id LIKE 'enrichments:custom:%' OR id = 'enrichments:code'
ON CONFLICT DO NOTHING;

-- ============================================================================
-- EDITOR ROLE: Grant create and code edit permissions
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'enrichments:code'),
    ('00000000-0000-0000-0000-000000000002', 'enrichments:custom:create'),
    ('00000000-0000-0000-0000-000000000002', 'enrichments:custom:delete')
ON CONFLICT DO NOTHING;
