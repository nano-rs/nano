-- Parser Repository Feature
-- Enables syncing VRL parsers from external GitHub repositories (public only)
-- Imported parsers become draft log sources ready for review and deployment

-- =============================================================================
-- External Parser Repositories Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS parser_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,              -- e.g., "nanos-sh/parsers"
    description TEXT,
    url TEXT NOT NULL,                       -- https://github.com/org/repo (public only)
    branch TEXT NOT NULL DEFAULT 'main',
    parsers_path TEXT DEFAULT 'parsers/',    -- Path to parsers folder in repo
    auto_sync_enabled BOOLEAN DEFAULT FALSE,
    sync_interval_hours INTEGER DEFAULT 24,
    last_synced_at TIMESTAMPTZ,
    last_sync_commit TEXT,
    last_sync_status TEXT,                   -- 'success' | 'failed' | 'syncing'
    last_sync_error TEXT,
    parser_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT parser_repositories_sync_status_check CHECK (last_sync_status IS NULL OR last_sync_status IN ('success', 'failed', 'syncing'))
);

COMMENT ON TABLE parser_repositories IS 'External parser repositories (public GitHub repos only)';
COMMENT ON COLUMN parser_repositories.slug IS 'URL-friendly identifier, e.g., nanos-sh/parsers';
COMMENT ON COLUMN parser_repositories.parsers_path IS 'Path to parsers folder within the repository';

-- =============================================================================
-- Cached Parsers from Repositories
-- =============================================================================

CREATE TABLE IF NOT EXISTS repository_parsers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES parser_repositories(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,                 -- e.g., "apache/parser.yaml"
    file_sha TEXT,                           -- Content hash for change detection
    raw_content TEXT NOT NULL,               -- Original YAML content
    -- Parsed metadata (extracted from YAML)
    name TEXT,
    display_name TEXT,
    description TEXT,
    version TEXT,
    category TEXT,
    vendor TEXT,
    product TEXT,
    parser_vrl TEXT,                         -- The VRL transformation code
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(repository_id, file_path)
);

COMMENT ON TABLE repository_parsers IS 'Cached parsers from external repositories';
COMMENT ON COLUMN repository_parsers.file_path IS 'Path to parser.yaml within repository';
COMMENT ON COLUMN repository_parsers.file_sha IS 'Content hash for detecting upstream changes';
COMMENT ON COLUMN repository_parsers.parser_vrl IS 'VRL transformation code extracted from YAML';

-- =============================================================================
-- Parser Imports (Link between repository parsers and log sources)
-- =============================================================================

CREATE TABLE IF NOT EXISTS parser_imports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_parser_id UUID NOT NULL REFERENCES repository_parsers(id) ON DELETE CASCADE,
    log_source_id UUID NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
    import_type TEXT NOT NULL,               -- 'linked' | 'forked'
    imported_at TIMESTAMPTZ DEFAULT NOW(),
    imported_by UUID REFERENCES users(id) ON DELETE SET NULL,
    imported_commit TEXT,                    -- Commit SHA when imported
    last_sync_commit TEXT,                   -- Last synced commit (for linked imports)
    upstream_changed BOOLEAN DEFAULT FALSE,  -- Flag when upstream has updates
    UNIQUE(repository_parser_id, log_source_id),
    CONSTRAINT parser_imports_type_check CHECK (import_type IN ('linked', 'forked'))
);

COMMENT ON TABLE parser_imports IS 'Tracks imports from repository parsers to log sources';
COMMENT ON COLUMN parser_imports.import_type IS 'linked = auto-update, forked = independent copy';
COMMENT ON COLUMN parser_imports.upstream_changed IS 'True when upstream parser has been updated since last sync';

-- =============================================================================
-- Log Sources Extensions
-- =============================================================================

-- Add source parser repository tracking to log_sources
ALTER TABLE log_sources
    ADD COLUMN IF NOT EXISTS source_parser_repository_id UUID REFERENCES parser_repositories(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS source_parser_path TEXT,
    ADD COLUMN IF NOT EXISTS source_parser_linked BOOLEAN DEFAULT FALSE;

COMMENT ON COLUMN log_sources.source_parser_repository_id IS 'Parser repository this log source was imported from (if any)';
COMMENT ON COLUMN log_sources.source_parser_path IS 'Path within the source parser repository';
COMMENT ON COLUMN log_sources.source_parser_linked IS 'Whether log source is linked for auto-updates from parser repo';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_parser_repos_enabled ON parser_repositories(enabled);
CREATE INDEX IF NOT EXISTS idx_parser_repos_slug ON parser_repositories(slug);
CREATE INDEX IF NOT EXISTS idx_repo_parsers_repo ON repository_parsers(repository_id);
CREATE INDEX IF NOT EXISTS idx_repo_parsers_name ON repository_parsers(name);
CREATE INDEX IF NOT EXISTS idx_parser_imports_log_source ON parser_imports(log_source_id);
CREATE INDEX IF NOT EXISTS idx_parser_imports_repo_parser ON parser_imports(repository_parser_id);
CREATE INDEX IF NOT EXISTS idx_parser_imports_upstream ON parser_imports(upstream_changed) WHERE upstream_changed = TRUE;
CREATE INDEX IF NOT EXISTS idx_log_sources_parser_repo ON log_sources(source_parser_repository_id);

-- =============================================================================
-- Permissions
-- =============================================================================

INSERT INTO permissions (id, name, description, category) VALUES
    ('parser_repositories:view', 'View Parser Repositories', 'View external parser repositories and browse parsers', 'log_sources'),
    ('parser_repositories:manage', 'Manage Parser Repositories', 'Create, edit, and delete parser repositories', 'log_sources'),
    ('parser_repositories:sync', 'Sync Parser Repositories', 'Trigger parser repository synchronization', 'log_sources'),
    ('parser_repositories:import', 'Import Repository Parsers', 'Import parsers from repositories as log sources', 'log_sources')
ON CONFLICT (id) DO NOTHING;

-- Grant permissions to Admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,  -- Admin role
    id
FROM permissions
WHERE id LIKE 'parser_repositories:%'
ON CONFLICT DO NOTHING;

-- Grant view permission to Analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000002'::uuid,  -- Analyst role
    id
FROM permissions
WHERE id = 'parser_repositories:view'
ON CONFLICT DO NOTHING;

-- =============================================================================
-- Updated timestamp trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION update_parser_repository_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_parser_repositories_timestamp
    BEFORE UPDATE ON parser_repositories
    FOR EACH ROW
    EXECUTE FUNCTION update_parser_repository_timestamp();

CREATE TRIGGER update_repository_parsers_timestamp
    BEFORE UPDATE ON repository_parsers
    FOR EACH ROW
    EXECUTE FUNCTION update_parser_repository_timestamp();
