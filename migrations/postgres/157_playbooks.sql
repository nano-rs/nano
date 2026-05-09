-- Playbooks Feature
--
-- SOC-managed playbook library. Parallels the rule_repositories pattern (071)
-- and parser_repositories pattern (090):
--   * Stock playbooks synced from an external git repo (default: nanos-sh/playbooks)
--   * Custom authored playbooks with draft → pending_review → live lifecycle
--   * Adaptive playbooks composed per-case by Shadow Investigator (promotable)
--   * Versions, runs, permissions, approvals
--
-- Playbook content is markdown + slash-commands (see design-ref/shadcn/playbook-parser.jsx).
-- Signal-based auto-attach: match_signals intersects rule.mitre_techniques and event types.

-- =============================================================================
-- External Playbook Repositories (mirror of rule_repositories)
-- =============================================================================

CREATE TABLE IF NOT EXISTS playbook_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,                          -- e.g., "nanos-sh/playbooks"
    description TEXT,
    url TEXT NOT NULL,                                  -- https://github.com/org/repo (public only)
    branch TEXT NOT NULL DEFAULT 'main',
    playbooks_path TEXT DEFAULT '',                     -- Path to playbooks within repo (empty = root)
    auto_sync_enabled BOOLEAN DEFAULT FALSE,
    sync_interval_hours INTEGER DEFAULT 24,
    last_synced_at TIMESTAMPTZ,
    last_sync_commit TEXT,
    last_sync_status TEXT,                              -- 'success' | 'failed' | 'syncing'
    last_sync_error TEXT,
    playbook_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT playbook_repositories_sync_status_check CHECK (last_sync_status IS NULL OR last_sync_status IN ('success', 'failed', 'syncing'))
);

COMMENT ON TABLE playbook_repositories IS 'External playbook repositories (public GitHub repos only)';
COMMENT ON COLUMN playbook_repositories.slug IS 'URL-friendly identifier, e.g., nanos-sh/playbooks';
COMMENT ON COLUMN playbook_repositories.playbooks_path IS 'Path to playbooks folder within the repository (empty = repo root)';
COMMENT ON COLUMN playbook_repositories.auto_sync_enabled IS 'Whether to automatically sync on schedule';

-- =============================================================================
-- Cached Playbooks from Repositories (mirror of repository_rules)
-- =============================================================================

CREATE TABLE IF NOT EXISTS repository_playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES playbook_repositories(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,                            -- e.g., "identity/credential_reuse.md"
    file_sha TEXT,                                      -- Git blob SHA for change detection
    raw_content TEXT NOT NULL,                          -- Original markdown (frontmatter + body)
    -- Parsed metadata (extracted from YAML frontmatter)
    title TEXT,
    subtitle TEXT,
    category TEXT,                                      -- identity | endpoint | cloud | data | network | email
    match_signals TEXT[] DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    owner_team TEXT,
    authored_date DATE,
    danger_policy JSONB,
    review_cadence TEXT,
    scope TEXT,
    -- Parse status
    parse_status TEXT DEFAULT 'pending',                -- 'pending' | 'success' | 'failed'
    parse_error TEXT,
    step_count INTEGER,                                 -- Count of slash-command steps after parsing
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(repository_id, file_path),
    CONSTRAINT repository_playbooks_parse_status_check CHECK (parse_status IN ('pending', 'success', 'failed')),
    CONSTRAINT repository_playbooks_category_check CHECK (category IS NULL OR category IN ('identity','endpoint','cloud','data','network','email'))
);

COMMENT ON TABLE repository_playbooks IS 'Cached playbooks from external repositories';
COMMENT ON COLUMN repository_playbooks.file_path IS 'Path to playbook file within repository (e.g., identity/credential_reuse.md)';
COMMENT ON COLUMN repository_playbooks.file_sha IS 'Git blob SHA for detecting upstream changes';
COMMENT ON COLUMN repository_playbooks.raw_content IS 'Full markdown content including YAML frontmatter';

-- =============================================================================
-- Main Playbooks Library Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),      -- TypeId prefix "pb" at serde layer
    title TEXT NOT NULL,
    subtitle TEXT,
    category TEXT NOT NULL,                             -- identity | endpoint | cloud | data | network | email
    doc TEXT NOT NULL,                                  -- Markdown + slash-command body (canonical spec)
    parsed_steps JSONB,                                 -- Cached step-tree from parser (fast UI reads)
    match_signals TEXT[] NOT NULL DEFAULT '{}',         -- Rule ids, event types, MITRE techniques
    danger_policy JSONB NOT NULL DEFAULT '{}',          -- {"action:high":"approval","action:medium":"auto",...}
    review_cadence TEXT NOT NULL DEFAULT '90d',
    scope TEXT NOT NULL DEFAULT 'tenant',               -- tenant | environment
    tags TEXT[] NOT NULL DEFAULT '{}',
    owner_team TEXT,
    maintainer_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'draft',               -- draft | pending_review | live | archived
    current_version INTEGER NOT NULL DEFAULT 1,
    -- Adaptive (agent-composed) tracking
    adaptive BOOLEAN NOT NULL DEFAULT FALSE,
    adaptive_source JSONB,                              -- {case_id, composed_at, composed_by, based_on:[pb_ids]}
    promoted BOOLEAN NOT NULL DEFAULT FALSE,
    -- External repo linkage (mirrors detection_rules.source_repository_id pattern)
    source_repository_id UUID REFERENCES playbook_repositories(id) ON DELETE SET NULL,
    source_playbook_path TEXT,
    source_linked BOOLEAN NOT NULL DEFAULT FALSE,       -- linked = auto-pull; false = forked/local
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    last_reviewed_at TIMESTAMPTZ,
    next_review_due_at TIMESTAMPTZ,
    CONSTRAINT playbooks_category_check CHECK (category IN ('identity','endpoint','cloud','data','network','email')),
    CONSTRAINT playbooks_status_check CHECK (status IN ('draft','pending_review','live','archived')),
    CONSTRAINT playbooks_scope_check CHECK (scope IN ('tenant','environment'))
);

COMMENT ON TABLE playbooks IS 'SOC-managed playbook library (stock synced + custom authored + adaptive)';
COMMENT ON COLUMN playbooks.doc IS 'Canonical markdown + slash-command body; parser produces parsed_steps cache';
COMMENT ON COLUMN playbooks.match_signals IS 'Signals that auto-attach this playbook: rule ids, event types, MITRE technique ids';
COMMENT ON COLUMN playbooks.danger_policy IS 'Per-danger-level policy: auto | approval | manual';
COMMENT ON COLUMN playbooks.adaptive IS 'True if agent-composed for a specific case (candidate for promotion)';
COMMENT ON COLUMN playbooks.source_linked IS 'True = auto-sync from upstream repo; false = forked/local';

-- =============================================================================
-- Playbook Imports (mirror of rule_imports)
-- =============================================================================

CREATE TABLE IF NOT EXISTS playbook_imports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_playbook_id UUID NOT NULL REFERENCES repository_playbooks(id) ON DELETE CASCADE,
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    import_type TEXT NOT NULL,                          -- 'linked' | 'forked'
    imported_at TIMESTAMPTZ DEFAULT NOW(),
    imported_by UUID REFERENCES users(id) ON DELETE SET NULL,
    imported_commit TEXT,
    last_sync_commit TEXT,
    upstream_changed BOOLEAN DEFAULT FALSE,
    customizations JSONB,                               -- Local modifications for forked playbooks
    UNIQUE(repository_playbook_id, playbook_id),
    CONSTRAINT playbook_imports_type_check CHECK (import_type IN ('linked', 'forked'))
);

COMMENT ON TABLE playbook_imports IS 'Tracks imports from repository playbooks into the local library';
COMMENT ON COLUMN playbook_imports.import_type IS 'linked = auto-update on upstream change; forked = independent copy';

-- =============================================================================
-- Playbook Versions (author + promotion history)
-- =============================================================================

CREATE TABLE IF NOT EXISTS playbook_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,                           -- Monotonic; matches playbooks.current_version when live
    doc TEXT NOT NULL,                                  -- Snapshot of the doc markdown at this version
    metadata JSONB NOT NULL,                            -- Snapshot: title, subtitle, category, match_signals, danger_policy, etc.
    note TEXT,                                          -- Author-supplied change note
    diff_added INTEGER DEFAULT 0,
    diff_removed INTEGER DEFAULT 0,
    author_id UUID REFERENCES users(id) ON DELETE SET NULL,
    author_name TEXT,                                   -- Cached for display (e.g., "agent" or a name if user deleted)
    promoted_from_case_id UUID,                         -- If this version was promoted from an adaptive run
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(playbook_id, version)
);

COMMENT ON TABLE playbook_versions IS 'Version history for playbooks; each save creates a new row';
COMMENT ON COLUMN playbook_versions.promoted_from_case_id IS 'Set when this version was promoted from an adaptive playbook composed for a specific case';

-- =============================================================================
-- Playbook Runs (per-case execution telemetry)
-- =============================================================================

CREATE TABLE IF NOT EXISTS playbook_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    playbook_version INTEGER NOT NULL,
    case_id UUID NOT NULL,                              -- No FK — cases may be purged; runs outlive them for analytics
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active',              -- active | resolved | abandoned
    operator_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    operator_label TEXT,                                -- Cached display label (e.g., "agent+Dan L." or a user name)
    outcome TEXT,                                       -- Free-form disposition ("credential-theft", "false-positive", ...)
    ttr_minutes INTEGER,                                -- Time-to-resolve, calculated on finish
    step_completion JSONB,                              -- Per-step state: {step_id: {completed_at, skipped, operator_note}}
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT playbook_runs_status_check CHECK (status IN ('active','resolved','abandoned'))
);

COMMENT ON TABLE playbook_runs IS 'Per-case execution of a playbook; source of analytics (attach/finish rate, TTR, skip rates)';
COMMENT ON COLUMN playbook_runs.step_completion IS 'JSONB keyed by step id: completion state, skip flag, operator note';

-- =============================================================================
-- Playbook Permissions (per-playbook role ACL)
-- =============================================================================

CREATE TABLE IF NOT EXISTS playbook_permissions (
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    role TEXT NOT NULL,                                 -- Free-form role label (e.g., "soc-leads", "soc-analysts")
    can_view BOOLEAN NOT NULL DEFAULT FALSE,
    can_run BOOLEAN NOT NULL DEFAULT FALSE,
    can_edit BOOLEAN NOT NULL DEFAULT FALSE,
    can_publish BOOLEAN NOT NULL DEFAULT FALSE,
    member_count INTEGER,                               -- Cached for display; nullable
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (playbook_id, role)
);

COMMENT ON TABLE playbook_permissions IS 'Per-playbook ACL: which roles can view/run/edit/publish';

-- =============================================================================
-- Playbook Approvals (submit-for-review → approve/reject workflow)
-- =============================================================================

CREATE TABLE IF NOT EXISTS playbook_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,                           -- The version being reviewed
    requester_id UUID REFERENCES users(id) ON DELETE SET NULL,
    approver_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',             -- pending | approved | rejected | withdrawn
    message TEXT,                                       -- Requester's message to approver
    response TEXT,                                      -- Approver's response note
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMPTZ,
    CONSTRAINT playbook_approvals_status_check CHECK (status IN ('pending','approved','rejected','withdrawn'))
);

COMMENT ON TABLE playbook_approvals IS 'Approval workflow for playbook drafts; pairs with playbooks.status = pending_review';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Repositories
CREATE INDEX IF NOT EXISTS idx_playbook_repos_enabled ON playbook_repositories(enabled);
CREATE INDEX IF NOT EXISTS idx_playbook_repos_slug ON playbook_repositories(slug);

-- Repository playbooks (cached)
CREATE INDEX IF NOT EXISTS idx_repo_playbooks_repo ON repository_playbooks(repository_id);
CREATE INDEX IF NOT EXISTS idx_repo_playbooks_category ON repository_playbooks(category);
CREATE INDEX IF NOT EXISTS idx_repo_playbooks_parse ON repository_playbooks(parse_status);

-- Main library
CREATE INDEX IF NOT EXISTS idx_playbooks_category ON playbooks(category);
CREATE INDEX IF NOT EXISTS idx_playbooks_status ON playbooks(status);
CREATE INDEX IF NOT EXISTS idx_playbooks_adaptive ON playbooks(adaptive) WHERE adaptive = TRUE;
CREATE INDEX IF NOT EXISTS idx_playbooks_promoted ON playbooks(promoted) WHERE promoted = TRUE;
CREATE INDEX IF NOT EXISTS idx_playbooks_source_repo ON playbooks(source_repository_id);
CREATE INDEX IF NOT EXISTS idx_playbooks_match_signals ON playbooks USING GIN(match_signals);
CREATE INDEX IF NOT EXISTS idx_playbooks_tags ON playbooks USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_playbooks_updated ON playbooks(updated_at DESC);

-- Imports
CREATE INDEX IF NOT EXISTS idx_playbook_imports_playbook ON playbook_imports(playbook_id);
CREATE INDEX IF NOT EXISTS idx_playbook_imports_repo_pb ON playbook_imports(repository_playbook_id);
CREATE INDEX IF NOT EXISTS idx_playbook_imports_upstream ON playbook_imports(upstream_changed) WHERE upstream_changed = TRUE;

-- Versions
CREATE INDEX IF NOT EXISTS idx_playbook_versions_playbook ON playbook_versions(playbook_id, version DESC);

-- Runs
CREATE INDEX IF NOT EXISTS idx_playbook_runs_playbook ON playbook_runs(playbook_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_case ON playbook_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_status ON playbook_runs(status) WHERE status = 'active';

-- Approvals
CREATE INDEX IF NOT EXISTS idx_playbook_approvals_playbook ON playbook_approvals(playbook_id);
CREATE INDEX IF NOT EXISTS idx_playbook_approvals_approver ON playbook_approvals(approver_id) WHERE status = 'pending';

-- =============================================================================
-- Permissions (app-level RBAC, not the per-playbook ACL above)
-- =============================================================================

INSERT INTO permissions (id, name, description, category) VALUES
    ('playbooks:view', 'View Playbooks', 'View the playbook library and open playbooks', 'detection'),
    ('playbooks:manage', 'Manage Playbooks', 'Create, edit, and archive playbooks', 'detection'),
    ('playbooks:run', 'Run Playbooks', 'Attach and execute playbooks on cases', 'detection'),
    ('playbooks:publish', 'Publish Playbooks', 'Approve drafts and publish playbooks to live status', 'detection'),
    ('playbook_repositories:view', 'View Playbook Repositories', 'View external playbook repositories and browse playbooks', 'detection'),
    ('playbook_repositories:manage', 'Manage Playbook Repositories', 'Create, edit, and delete playbook repositories', 'detection'),
    ('playbook_repositories:sync', 'Sync Playbook Repositories', 'Trigger repository synchronization', 'detection'),
    ('playbook_repositories:import', 'Import Repository Playbooks', 'Import playbooks from repositories into the library', 'detection')
ON CONFLICT (id) DO NOTHING;

-- Grant full access to Admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    id
FROM permissions
WHERE id LIKE 'playbooks:%' OR id LIKE 'playbook_repositories:%'
ON CONFLICT DO NOTHING;

-- Grant view + run to Analyst role (no manage/publish/repo admin)
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000002'::uuid,
    id
FROM permissions
WHERE id IN ('playbooks:view', 'playbooks:run', 'playbook_repositories:view')
ON CONFLICT DO NOTHING;

-- =============================================================================
-- Updated-timestamp triggers
-- =============================================================================

CREATE OR REPLACE FUNCTION update_playbook_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_playbook_repositories_timestamp
    BEFORE UPDATE ON playbook_repositories
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

CREATE TRIGGER update_repository_playbooks_timestamp
    BEFORE UPDATE ON repository_playbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

CREATE TRIGGER update_playbooks_timestamp
    BEFORE UPDATE ON playbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

CREATE TRIGGER update_playbook_permissions_timestamp
    BEFORE UPDATE ON playbook_permissions
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_timestamp();

-- =============================================================================
-- Seed default repository (nanos-sh/playbooks)
-- =============================================================================

INSERT INTO playbook_repositories (name, slug, description, url, branch, playbooks_path, auto_sync_enabled, enabled)
VALUES (
    'nano Playbooks',
    'nanos-sh/playbooks',
    'Official nano playbook library — stock SOC investigation playbooks across identity, endpoint, cloud, data, network, and email categories.',
    'https://github.com/nanos-sh/playbooks',
    'main',
    '',
    FALSE,
    TRUE
)
ON CONFLICT (slug) DO NOTHING;
