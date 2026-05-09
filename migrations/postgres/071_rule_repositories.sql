-- Rule Repository Feature
-- Enables syncing detection rules from external GitHub repositories (public only)
-- Supports Sigma rule conversion to nPL via AI
-- Tracks linked vs forked rules for update management

-- =============================================================================
-- External Rule Repositories Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS rule_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,              -- e.g., "sigma-hq/sigma"
    description TEXT,
    url TEXT NOT NULL,                       -- https://github.com/org/repo (public only)
    branch TEXT NOT NULL DEFAULT 'main',
    rules_path TEXT DEFAULT 'rules/',        -- Path to rules folder in repo
    rule_format TEXT NOT NULL DEFAULT 'sigma', -- 'sigma' | 'nanosiem'
    -- No auth_token - public repos only (open source for life!)
    auto_sync_enabled BOOLEAN DEFAULT FALSE,
    sync_interval_hours INTEGER DEFAULT 24,
    last_synced_at TIMESTAMPTZ,
    last_sync_commit TEXT,
    last_sync_status TEXT,                   -- 'success' | 'failed' | 'syncing'
    last_sync_error TEXT,
    rule_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT rule_repositories_format_check CHECK (rule_format IN ('sigma', 'nanosiem')),
    CONSTRAINT rule_repositories_sync_status_check CHECK (last_sync_status IS NULL OR last_sync_status IN ('success', 'failed', 'syncing'))
);

COMMENT ON TABLE rule_repositories IS 'External rule repositories (public GitHub repos only)';
COMMENT ON COLUMN rule_repositories.slug IS 'URL-friendly identifier, e.g., sigma-hq/sigma';
COMMENT ON COLUMN rule_repositories.rules_path IS 'Path to rules folder within the repository';
COMMENT ON COLUMN rule_repositories.rule_format IS 'Format of rules in repository: sigma or nanosiem';
COMMENT ON COLUMN rule_repositories.auto_sync_enabled IS 'Whether to automatically sync on schedule';
COMMENT ON COLUMN rule_repositories.sync_interval_hours IS 'Hours between automatic syncs';

-- =============================================================================
-- Cached Rules from Repositories
-- =============================================================================

CREATE TABLE IF NOT EXISTS repository_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES rule_repositories(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,                 -- e.g., "windows/process_creation/mimikatz.yml"
    file_sha TEXT,                           -- Git blob SHA for change detection
    raw_content TEXT NOT NULL,               -- Original YAML content
    -- Parsed metadata (extracted from YAML)
    title TEXT,
    description TEXT,
    severity TEXT,
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    tags TEXT[],
    -- UDM requirements (what fields/sources this rule needs)
    requires_fields TEXT[],                  -- UDM fields needed
    requires_source_types TEXT[],            -- Suggested source types
    -- Conversion status (for Sigma rules)
    conversion_status TEXT DEFAULT 'pending', -- 'pending' | 'success' | 'failed' | 'manual'
    converted_npl TEXT,                      -- AI-converted nPL query
    conversion_confidence FLOAT,             -- 0.0-1.0 confidence score
    conversion_warnings TEXT[],              -- Warnings from conversion
    conversion_field_mappings JSONB,         -- {sigma_field: udm_field}
    -- Coverage analysis
    coverage_status TEXT,                    -- 'full' | 'partial' | 'none'
    coverage_missing_fields TEXT[],          -- Fields required but not available
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(repository_id, file_path),
    CONSTRAINT repository_rules_conversion_status_check CHECK (conversion_status IN ('pending', 'success', 'failed', 'manual')),
    CONSTRAINT repository_rules_coverage_status_check CHECK (coverage_status IS NULL OR coverage_status IN ('full', 'partial', 'none')),
    CONSTRAINT repository_rules_confidence_check CHECK (conversion_confidence IS NULL OR (conversion_confidence >= 0.0 AND conversion_confidence <= 1.0))
);

COMMENT ON TABLE repository_rules IS 'Cached rules from external repositories';
COMMENT ON COLUMN repository_rules.file_path IS 'Path to rule file within repository';
COMMENT ON COLUMN repository_rules.file_sha IS 'Git blob SHA for detecting upstream changes';
COMMENT ON COLUMN repository_rules.requires_fields IS 'UDM fields required for this rule to work';
COMMENT ON COLUMN repository_rules.conversion_status IS 'Status of Sigma to nPL conversion';
COMMENT ON COLUMN repository_rules.converted_npl IS 'AI-converted nPL query (for Sigma rules)';
COMMENT ON COLUMN repository_rules.coverage_status IS 'Whether required fields are available in logs';

-- =============================================================================
-- Rule Imports (Link between repository rules and detection rules)
-- =============================================================================

CREATE TABLE IF NOT EXISTS rule_imports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_rule_id UUID NOT NULL REFERENCES repository_rules(id) ON DELETE CASCADE,
    detection_rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    import_type TEXT NOT NULL,               -- 'linked' | 'forked'
    imported_at TIMESTAMPTZ DEFAULT NOW(),
    imported_by UUID REFERENCES users(id) ON DELETE SET NULL,
    imported_commit TEXT,                    -- Commit SHA when imported
    last_sync_commit TEXT,                   -- Last synced commit (for linked rules)
    upstream_changed BOOLEAN DEFAULT FALSE,  -- Flag when upstream has updates
    customizations JSONB,                    -- Track local modifications (for forked)
    UNIQUE(repository_rule_id, detection_rule_id),
    CONSTRAINT rule_imports_type_check CHECK (import_type IN ('linked', 'forked'))
);

COMMENT ON TABLE rule_imports IS 'Tracks imports from repository rules to detection rules';
COMMENT ON COLUMN rule_imports.import_type IS 'linked = auto-update, forked = independent copy';
COMMENT ON COLUMN rule_imports.upstream_changed IS 'True when upstream rule has been updated since last sync';
COMMENT ON COLUMN rule_imports.customizations IS 'JSON tracking local modifications for forked rules';

-- =============================================================================
-- Detection Rules Extensions
-- =============================================================================

-- Add source repository tracking to detection_rules
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS source_repository_id UUID REFERENCES rule_repositories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS source_rule_path TEXT,
    ADD COLUMN IF NOT EXISTS source_linked BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS requires_fields TEXT[] DEFAULT '{}';

COMMENT ON COLUMN detection_rules.source_repository_id IS 'Repository this rule was imported from (if any)';
COMMENT ON COLUMN detection_rules.source_rule_path IS 'Path within the source repository';
COMMENT ON COLUMN detection_rules.source_linked IS 'Whether rule is linked for auto-updates';
COMMENT ON COLUMN detection_rules.requires_fields IS 'UDM fields required for this rule';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_rule_repos_enabled ON rule_repositories(enabled);
CREATE INDEX IF NOT EXISTS idx_rule_repos_slug ON rule_repositories(slug);
CREATE INDEX IF NOT EXISTS idx_repo_rules_repo ON repository_rules(repository_id);
CREATE INDEX IF NOT EXISTS idx_repo_rules_coverage ON repository_rules(coverage_status);
CREATE INDEX IF NOT EXISTS idx_repo_rules_conversion ON repository_rules(conversion_status);
CREATE INDEX IF NOT EXISTS idx_repo_rules_severity ON repository_rules(severity);
CREATE INDEX IF NOT EXISTS idx_rule_imports_detection ON rule_imports(detection_rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_imports_repo_rule ON rule_imports(repository_rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_imports_upstream ON rule_imports(upstream_changed) WHERE upstream_changed = TRUE;
CREATE INDEX IF NOT EXISTS idx_detection_rules_source ON detection_rules(source_repository_id);
CREATE INDEX IF NOT EXISTS idx_detection_rules_requires ON detection_rules USING GIN(requires_fields);

-- =============================================================================
-- Permissions
-- =============================================================================

INSERT INTO permissions (id, name, description, category) VALUES
    ('rule_repositories:view', 'View Rule Repositories', 'View external rule repositories and browse rules', 'detection'),
    ('rule_repositories:manage', 'Manage Rule Repositories', 'Create, edit, and delete rule repositories', 'detection'),
    ('rule_repositories:sync', 'Sync Rule Repositories', 'Trigger repository synchronization', 'detection'),
    ('rule_repositories:import', 'Import Repository Rules', 'Import rules from repositories into detections', 'detection')
ON CONFLICT (id) DO NOTHING;

-- Grant permissions to Admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,  -- Admin role
    id
FROM permissions
WHERE id LIKE 'rule_repositories:%'
ON CONFLICT DO NOTHING;

-- Grant view permission to Analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000002'::uuid,  -- Analyst role
    id
FROM permissions
WHERE id = 'rule_repositories:view'
ON CONFLICT DO NOTHING;

-- =============================================================================
-- Updated timestamp trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION update_rule_repository_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_rule_repositories_timestamp
    BEFORE UPDATE ON rule_repositories
    FOR EACH ROW
    EXECUTE FUNCTION update_rule_repository_timestamp();

CREATE TRIGGER update_repository_rules_timestamp
    BEFORE UPDATE ON repository_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_rule_repository_timestamp();
