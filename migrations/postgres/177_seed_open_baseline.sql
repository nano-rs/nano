-- NAN-791 (NAN-790 follow-up): open-tier baseline data for fresh deploys.
--
-- Supersedes 176_seed_baseline_fresh_deploy.sql (deleted in the same commit).
-- The old 176 bundled enterprise-only seeds (melod_settings, agent_model_config,
-- case_grouping_rules) into an open-tier migration, so it crashed with
-- `relation "melod_settings" does not exist` on fresh deploys after NAN-791's
-- backfill cutoff started letting 176 actually execute. The enterprise seeds
-- have been relocated to `postgres-enterprise/9000003_seed_enterprise_baseline.sql`,
-- which runs after the enterprise overlay creates those tables.
--
-- 176 stays deleted. `open_migrator.set_ignore_missing(true)` (see
-- `nanosiem-core/src/db/migrations.rs`) tolerates the orphan `_sqlx_migrations`
-- row left behind on tenants that already backfilled or ran the old 176.
--
-- This migration re-runs the open-tier INSERTs idempotently. On legacy tenants
-- every row already exists, so `ON CONFLICT ... DO NOTHING` (and
-- `WHERE NOT EXISTS` for the license_status singleton) makes the whole file a
-- no-op. On fresh tenants it backfills the open baseline.
--
-- Carve-outs (NOT seeded here):
--   * 040_litellm_provider_config.sql — litellm is no longer used.
--   * 009 lines 72–167 — data migration parsers→log_sources from a now-removed
--     schema; would error on fresh DB.
--   * 083 — data migration log_sources→log_source_versions; safe to skip
--     because log_sources is empty on a fresh DB.
--   * 154/155 queues — those reference CTE-bound group IDs from within their
--     own transactions. Cases UI bootstraps queue groups on first use, so this
--     is not setup-blocking. A follow-up migration can backfill queue defaults
--     once the queue-group helper is extracted.
--   * Enterprise-only seeds (melod_settings, agent_model_config,
--     case_grouping_rules) — moved to postgres-enterprise/9000003 (NAN-791).
--
-- Follow-up: fix tools/nan749_split_open_overlay.py so the next snapshot
-- regeneration captures INSERT data (e.g. pg_dump --inserts instead of
-- --schema-only). Without that, this gap re-opens on every regen.

-- ============================================================================
-- PERMISSIONS — collected from 001, 007, 009, 018, 019, 026, 028, 039, 047,
-- 055, 071, 074, 090, 093, 099, 104, 128, 129, 149
-- ============================================================================

-- 001 baseline permissions catalogue
INSERT INTO permissions (id, name, description, category) VALUES
    -- Search
    ('search:view', 'View Search', 'Access the search interface', 'search'),
    ('search:execute', 'Execute Search', 'Run search queries', 'search'),
    ('search:save', 'Save Search', 'Save search queries', 'search'),
    ('search:share', 'Share Search', 'Share search queries with others', 'search'),
    -- Dashboards
    ('dashboards:view', 'View Dashboards', 'View dashboards', 'dashboards'),
    ('dashboards:create', 'Create Dashboards', 'Create new dashboards', 'dashboards'),
    ('dashboards:edit', 'Edit Dashboards', 'Modify existing dashboards', 'dashboards'),
    ('dashboards:delete', 'Delete Dashboards', 'Delete dashboards', 'dashboards'),
    -- Detections
    ('detections:view', 'View Detections', 'View detection rules', 'detections'),
    ('detections:create', 'Create Detections', 'Create new detection rules', 'detections'),
    ('detections:edit', 'Edit Detections', 'Modify detection rules', 'detections'),
    ('detections:delete', 'Delete Detections', 'Delete detection rules', 'detections'),
    ('detections:enable', 'Enable/Disable Detections', 'Enable or disable detection rules', 'detections'),
    ('detections:promote', 'Promote/Demote Detections', 'Change detection rule mode', 'detections'),
    -- Alerts
    ('alerts:view', 'View Alerts', 'View alerts', 'alerts'),
    ('alerts:acknowledge', 'Acknowledge Alerts', 'Acknowledge alerts', 'alerts'),
    ('alerts:close', 'Close Alerts', 'Close alerts', 'alerts'),
    ('alerts:assign', 'Assign Alerts', 'Assign alerts to users', 'alerts'),
    -- Parsers
    ('parsers:view', 'View Parsers', 'View parser configurations', 'parsers'),
    ('parsers:create', 'Create Parsers', 'Create new parsers', 'parsers'),
    ('parsers:edit', 'Edit Parsers', 'Modify parser configurations', 'parsers'),
    ('parsers:delete', 'Delete Parsers', 'Delete parsers', 'parsers'),
    ('parsers:deploy', 'Deploy Parsers', 'Deploy parsers to Vector', 'parsers'),
    -- Feeds
    ('feeds:view', 'View Feeds', 'View data feeds', 'feeds'),
    ('feeds:create', 'Create Feeds', 'Create new feeds', 'feeds'),
    ('feeds:edit', 'Edit Feeds', 'Modify feed configurations', 'feeds'),
    ('feeds:delete', 'Delete Feeds', 'Delete feeds', 'feeds'),
    -- Enrichments
    ('enrichments:view', 'View Enrichments', 'View enrichment sources', 'enrichments'),
    ('enrichments:configure', 'Configure Enrichments', 'Configure enrichment sources', 'enrichments'),
    -- Lookup tables
    ('lookup:view', 'View Lookup Tables', 'View lookup tables', 'lookup'),
    ('lookup:create', 'Create Lookup Tables', 'Create lookup tables', 'lookup'),
    ('lookup:edit', 'Edit Lookup Tables', 'Modify lookup tables', 'lookup'),
    ('lookup:delete', 'Delete Lookup Tables', 'Delete lookup tables', 'lookup'),
    -- Risk analytics
    ('risk:view', 'View Risk Analytics', 'View risk scores and analytics', 'risk'),
    ('risk:configure', 'Configure Risk', 'Configure risk scoring settings', 'risk'),
    ('risk:clear', 'Clear Risk Scores', 'Clear entity risk scores', 'risk'),
    -- Prevalence
    ('prevalence:view', 'View Prevalence', 'View prevalence tracking data', 'prevalence'),
    ('prevalence:configure', 'Configure Prevalence', 'Configure prevalence tracking settings', 'prevalence'),
    ('prevalence:export', 'Export Prevalence', 'Export prevalence data', 'prevalence'),
    -- Settings
    ('settings:view', 'View Settings', 'View system settings', 'settings'),
    ('settings:system', 'System Settings', 'Modify system settings', 'settings'),
    ('settings:retention', 'Retention Settings', 'Modify data retention settings', 'settings'),
    ('settings:ai', 'AI Settings', 'Modify AI/meloD settings', 'settings'),
    ('settings:risk', 'Risk Settings', 'Modify risk scoring settings', 'settings'),
    -- User management
    ('users:view', 'View Users', 'View user accounts', 'users'),
    ('users:create', 'Create Users', 'Create user accounts', 'users'),
    ('users:edit', 'Edit Users', 'Modify user accounts', 'users'),
    ('users:delete', 'Delete Users', 'Delete user accounts', 'users'),
    -- Groups
    ('groups:view', 'View Groups', 'View groups', 'groups'),
    ('groups:create', 'Create Groups', 'Create groups', 'groups'),
    ('groups:edit', 'Edit Groups', 'Modify groups', 'groups'),
    ('groups:delete', 'Delete Groups', 'Delete groups', 'groups'),
    -- Roles
    ('roles:view', 'View Roles', 'View roles', 'roles'),
    ('roles:create', 'Create Roles', 'Create roles', 'roles'),
    ('roles:edit', 'Edit Roles', 'Modify roles', 'roles'),
    ('roles:delete', 'Delete Roles', 'Delete roles', 'roles'),
    -- API keys
    ('apikeys:view', 'View API Keys', 'View API keys', 'apikeys'),
    ('apikeys:create', 'Create API Keys', 'Create API keys', 'apikeys'),
    ('apikeys:delete', 'Delete API Keys', 'Delete API keys', 'apikeys'),
    -- Audit
    ('audit:view', 'View Audit Logs', 'View audit logs', 'audit')
ON CONFLICT (id) DO NOTHING;

-- 007 cloud credentials
INSERT INTO permissions (id, name, description, category) VALUES
    ('credentials:view', 'View Credentials', 'View cloud storage credentials', 'credentials'),
    ('credentials:create', 'Create Credentials', 'Create new cloud storage credentials', 'credentials'),
    ('credentials:edit', 'Edit Credentials', 'Modify cloud storage credentials', 'credentials'),
    ('credentials:delete', 'Delete Credentials', 'Remove cloud storage credentials', 'credentials')
ON CONFLICT (id) DO NOTHING;

-- 009 log sources
INSERT INTO permissions (id, name, description, category) VALUES
    ('log_sources:view', 'View Log Sources', 'View log source configurations', 'log_sources'),
    ('log_sources:create', 'Create Log Sources', 'Create new log sources', 'log_sources'),
    ('log_sources:edit', 'Edit Log Sources', 'Modify log source configurations', 'log_sources'),
    ('log_sources:delete', 'Delete Log Sources', 'Delete log sources', 'log_sources'),
    ('log_sources:deploy', 'Deploy Log Sources', 'Deploy log sources to Vector', 'log_sources')
ON CONFLICT (id) DO NOTHING;

-- 018 alerts triage
INSERT INTO permissions (id, name, description, category) VALUES
    ('alerts:triage', 'Triage Alerts', 'Initiate AI-powered alert triage and analysis', 'alerts')
ON CONFLICT (id) DO NOTHING;

-- 019 cases
INSERT INTO permissions (id, name, description, category) VALUES
    ('cases:view', 'cases:view', 'View cases and case details', 'cases'),
    ('cases:create', 'cases:create', 'Create new cases manually', 'cases'),
    ('cases:edit', 'cases:edit', 'Edit case details and add comments', 'cases'),
    ('cases:assign', 'cases:assign', 'Assign cases to users', 'cases'),
    ('cases:close', 'cases:close', 'Close and resolve cases', 'cases'),
    ('cases:delete', 'cases:delete', 'Delete cases', 'cases'),
    ('case_settings:view', 'case_settings:view', 'View case grouping settings', 'settings'),
    ('case_settings:edit', 'case_settings:edit', 'Edit case grouping rules', 'settings')
ON CONFLICT (id) DO NOTHING;

-- 026 notifications
INSERT INTO permissions (id, name, description, category) VALUES
    ('notifications:view', 'notifications:view', 'View own notifications', 'notifications'),
    ('notifications:manage', 'notifications:manage', 'Manage notification settings', 'notifications')
ON CONFLICT (id) DO NOTHING;

-- 028 melod
INSERT INTO permissions (id, name, description, category) VALUES
    ('melod:chat', 'Chat with AI', 'Use AI chat and general assistance', 'melod'),
    ('melod:query', 'Build Queries', 'Use AI to build search queries from natural language', 'melod'),
    ('melod:parser', 'Create Parsers', 'Use AI to generate log parsers', 'melod'),
    ('melod:detection', 'Create Detections', 'Use AI to create and tune detection rules', 'melod'),
    ('melod:summarize', 'Summarize Results', 'Use AI to summarize search results', 'melod'),
    ('melod:dashboard', 'Generate Dashboards', 'Use AI to generate dashboard configurations', 'melod'),
    ('melod:notebook', 'Notebook AI', 'Use AI features in notebooks (timeline, suggestions)', 'melod')
ON CONFLICT (id) DO NOTHING;

-- 039 mitre
INSERT INTO permissions (id, name, description, category) VALUES
    ('mitre:view', 'View MITRE Data', 'View MITRE ATT&CK tactics, techniques, and coverage', 'mitre'),
    ('mitre:sync', 'Sync MITRE Data', 'Trigger sync of MITRE ATT&CK data from GitHub', 'mitre')
ON CONFLICT (id) DO NOTHING;

-- 047 source configurations
INSERT INTO permissions (id, name, description, category) VALUES
    ('source_configs:view', 'View Source Configurations', 'View source configuration settings', 'source_configs'),
    ('source_configs:create', 'Create Source Configurations', 'Create new source configurations', 'source_configs'),
    ('source_configs:edit', 'Edit Source Configurations', 'Modify source configuration settings', 'source_configs'),
    ('source_configs:delete', 'Delete Source Configurations', 'Remove source configurations', 'source_configs'),
    ('source_configs:deploy', 'Deploy Source Configurations', 'Deploy source configurations to Vector', 'source_configs')
ON CONFLICT (id) DO NOTHING;

-- 055 custom enrichments
INSERT INTO permissions (id, name, description, category) VALUES
    ('enrichments:code', 'Edit Enrichment Code', 'Access the manual code editor for enrichments', 'enrichments'),
    ('enrichments:custom:create', 'Create Custom Enrichments', 'Create and edit custom enrichments with AI code generation', 'enrichments'),
    ('enrichments:custom:delete', 'Delete Custom Enrichments', 'Delete custom enrichments', 'enrichments')
ON CONFLICT (id) DO NOTHING;

-- 071 rule repositories
INSERT INTO permissions (id, name, description, category) VALUES
    ('rule_repositories:view', 'View Rule Repositories', 'View external rule repositories and browse rules', 'detection'),
    ('rule_repositories:manage', 'Manage Rule Repositories', 'Create, edit, and delete rule repositories', 'detection'),
    ('rule_repositories:sync', 'Sync Rule Repositories', 'Trigger repository synchronization', 'detection'),
    ('rule_repositories:import', 'Import Repository Rules', 'Import rules from repositories into detections', 'detection')
ON CONFLICT (id) DO NOTHING;

-- 074 webhooks
INSERT INTO permissions (id, name, description, category) VALUES
    ('settings:webhooks', 'Manage Webhooks', 'Manage webhook notification endpoints', 'settings')
ON CONFLICT (id) DO NOTHING;

-- 090 parser repositories
INSERT INTO permissions (id, name, description, category) VALUES
    ('parser_repositories:view', 'View Parser Repositories', 'View external parser repositories and browse parsers', 'log_sources'),
    ('parser_repositories:manage', 'Manage Parser Repositories', 'Create, edit, and delete parser repositories', 'log_sources'),
    ('parser_repositories:sync', 'Sync Parser Repositories', 'Trigger parser repository synchronization', 'log_sources'),
    ('parser_repositories:import', 'Import Repository Parsers', 'Import parsers from repositories as log sources', 'log_sources')
ON CONFLICT (id) DO NOTHING;

-- 093 notebooks
INSERT INTO permissions (id, name, description, category) VALUES
    ('notebooks:view', 'View Notebooks', 'View investigation notebooks', 'notebooks'),
    ('notebooks:create', 'Create Notebooks', 'Create new investigation notebooks', 'notebooks'),
    ('notebooks:edit', 'Edit Notebooks', 'Edit investigation notebooks', 'notebooks'),
    ('notebooks:delete', 'Delete Notebooks', 'Delete investigation notebooks', 'notebooks'),
    ('notebooks:share', 'Share Notebooks', 'Share investigation notebooks with others', 'notebooks')
ON CONFLICT (id) DO NOTHING;

-- 099 apikeys edit
INSERT INTO permissions (id, name, description, category) VALUES
    ('apikeys:edit', 'Edit API Keys', 'Update, enable, disable, and reset API keys', 'apikeys')
ON CONFLICT (id) DO NOTHING;

-- 104 gdpr
INSERT INTO permissions (id, name, description, category) VALUES
    ('gdpr:anonymize', 'gdpr:anonymize', 'Execute GDPR data subject anonymization', 'gdpr')
ON CONFLICT (id) DO NOTHING;

-- 128 new permissions
INSERT INTO permissions (id, name, description, category) VALUES
    ('detections:export', 'detections:export', 'Export detection rules', 'detections'),
    ('sessions:admin', 'sessions:admin', 'View and manage all user sessions', 'sessions')
ON CONFLICT (id) DO NOTHING;

-- 129 search sql
INSERT INTO permissions (id, name, description, category) VALUES
    ('search:sql', 'search:sql', 'Execute raw SQL queries against ClickHouse', 'search')
ON CONFLICT (id) DO NOTHING;

-- 149 seed missing permissions
INSERT INTO permissions (id, name, description, category) VALUES
    ('cases:comment', 'Comment on Cases', 'Add comments to cases', 'cases'),
    ('cases:share', 'Share Cases', 'Share cases with other users', 'cases'),
    ('upload:logs', 'Upload Logs', 'Upload log files for ingestion', 'upload'),
    ('upload:history', 'View Upload History', 'View log upload history and status', 'upload')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ROLES (001) — Admin / Editor / ReadOnly at well-known UUIDs
-- ============================================================================

-- ON CONFLICT (id) — the well-known UUIDs are the load-bearing invariant
-- (group_roles + setup/initialize hardcode them). Tenants who renamed
-- 'Admin' → 'Administrator' etc. would trip a PK collision under
-- ON CONFLICT (name); keying on id no-ops cleanly and preserves their
-- custom names.
INSERT INTO roles (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Admin', 'Full system access with all permissions', TRUE),
    ('00000000-0000-0000-0000-000000000002', 'Editor', 'Create and manage detections, parsers, and dashboards', TRUE),
    ('00000000-0000-0000-0000-000000000003', 'ReadOnly', 'View-only access for search and monitoring', TRUE)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- GROUPS (001) — Everyone default group; FK target for setup/initialize
-- ============================================================================

-- ON CONFLICT (id) — same rationale as the roles INSERT above; the
-- 00…0001 UUID is referenced explicitly by group_roles and the auth code.
INSERT INTO groups (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Everyone', 'Default group that all users belong to', TRUE)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ROLE PERMISSIONS — Admin gets everything (uses 033's SELECT-everything
-- pattern so future permissions are auto-granted); Editor + ReadOnly subsets
-- explicit from 001; per-feature additions from 007, 019, 026, 028, 039, 047,
-- 055, 071, 074, 090, 093, 099, 104, 128, 129, 149
-- ============================================================================

-- Admin: every permission (covers 033's intent and all later permission migrations)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id FROM permissions
ON CONFLICT DO NOTHING;

-- Editor: 001's curated subset + later additions
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'search:view'),
    ('00000000-0000-0000-0000-000000000002', 'search:execute'),
    ('00000000-0000-0000-0000-000000000002', 'search:save'),
    ('00000000-0000-0000-0000-000000000002', 'search:share'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:view'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:create'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:edit'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:delete'),
    ('00000000-0000-0000-0000-000000000002', 'detections:view'),
    ('00000000-0000-0000-0000-000000000002', 'detections:create'),
    ('00000000-0000-0000-0000-000000000002', 'detections:edit'),
    ('00000000-0000-0000-0000-000000000002', 'detections:delete'),
    ('00000000-0000-0000-0000-000000000002', 'detections:enable'),
    ('00000000-0000-0000-0000-000000000002', 'detections:promote'),
    ('00000000-0000-0000-0000-000000000002', 'alerts:view'),
    ('00000000-0000-0000-0000-000000000002', 'alerts:acknowledge'),
    ('00000000-0000-0000-0000-000000000002', 'alerts:close'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:view'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:create'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:edit'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:delete'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:deploy'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:view'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:create'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:edit'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:delete'),
    ('00000000-0000-0000-0000-000000000002', 'enrichments:view'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:view'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:create'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:edit'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:delete'),
    ('00000000-0000-0000-0000-000000000002', 'prevalence:view'),
    ('00000000-0000-0000-0000-000000000002', 'prevalence:export'),
    ('00000000-0000-0000-0000-000000000002', 'risk:view'),
    ('00000000-0000-0000-0000-000000000002', 'settings:view'),
    -- Editor adds from later migrations
    ('00000000-0000-0000-0000-000000000002', 'credentials:view'),
    ('00000000-0000-0000-0000-000000000002', 'log_sources:view'),
    ('00000000-0000-0000-0000-000000000002', 'log_sources:edit'),
    ('00000000-0000-0000-0000-000000000002', 'log_sources:deploy'),
    ('00000000-0000-0000-0000-000000000002', 'source_configs:view'),
    ('00000000-0000-0000-0000-000000000002', 'source_configs:edit'),
    ('00000000-0000-0000-0000-000000000002', 'source_configs:deploy'),
    ('00000000-0000-0000-0000-000000000002', 'mitre:view'),
    ('00000000-0000-0000-0000-000000000002', 'mitre:sync'),
    ('00000000-0000-0000-0000-000000000002', 'melod:chat'),
    ('00000000-0000-0000-0000-000000000002', 'melod:query'),
    ('00000000-0000-0000-0000-000000000002', 'melod:parser'),
    ('00000000-0000-0000-0000-000000000002', 'melod:detection'),
    ('00000000-0000-0000-0000-000000000002', 'melod:summarize'),
    ('00000000-0000-0000-0000-000000000002', 'melod:dashboard'),
    ('00000000-0000-0000-0000-000000000002', 'melod:notebook'),
    ('00000000-0000-0000-0000-000000000002', 'enrichments:code'),
    ('00000000-0000-0000-0000-000000000002', 'enrichments:custom:create'),
    ('00000000-0000-0000-0000-000000000002', 'enrichments:custom:delete'),
    ('00000000-0000-0000-0000-000000000002', 'cases:view'),
    ('00000000-0000-0000-0000-000000000002', 'cases:create'),
    ('00000000-0000-0000-0000-000000000002', 'cases:edit'),
    ('00000000-0000-0000-0000-000000000002', 'cases:assign'),
    ('00000000-0000-0000-0000-000000000002', 'cases:close'),
    ('00000000-0000-0000-0000-000000000002', 'cases:comment'),
    ('00000000-0000-0000-0000-000000000002', 'cases:share'),
    ('00000000-0000-0000-0000-000000000002', 'notifications:view'),
    ('00000000-0000-0000-0000-000000000002', 'notebooks:view'),
    ('00000000-0000-0000-0000-000000000002', 'notebooks:create'),
    ('00000000-0000-0000-0000-000000000002', 'notebooks:edit'),
    ('00000000-0000-0000-0000-000000000002', 'notebooks:share'),
    ('00000000-0000-0000-0000-000000000002', 'detections:export'),
    ('00000000-0000-0000-0000-000000000002', 'search:sql'),
    ('00000000-0000-0000-0000-000000000002', 'rule_repositories:view'),
    ('00000000-0000-0000-0000-000000000002', 'parser_repositories:view')
ON CONFLICT DO NOTHING;

-- ReadOnly: 001's curated subset + later view-only additions
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000003', 'search:view'),
    ('00000000-0000-0000-0000-000000000003', 'search:execute'),
    ('00000000-0000-0000-0000-000000000003', 'dashboards:view'),
    ('00000000-0000-0000-0000-000000000003', 'detections:view'),
    ('00000000-0000-0000-0000-000000000003', 'alerts:view'),
    ('00000000-0000-0000-0000-000000000003', 'parsers:view'),
    ('00000000-0000-0000-0000-000000000003', 'feeds:view'),
    ('00000000-0000-0000-0000-000000000003', 'enrichments:view'),
    ('00000000-0000-0000-0000-000000000003', 'lookup:view'),
    ('00000000-0000-0000-0000-000000000003', 'prevalence:view'),
    ('00000000-0000-0000-0000-000000000003', 'risk:view'),
    -- ReadOnly view-only additions from later migrations
    ('00000000-0000-0000-0000-000000000003', 'credentials:view'),
    ('00000000-0000-0000-0000-000000000003', 'log_sources:view'),
    ('00000000-0000-0000-0000-000000000003', 'source_configs:view'),
    ('00000000-0000-0000-0000-000000000003', 'mitre:view'),
    ('00000000-0000-0000-0000-000000000003', 'melod:chat'),
    ('00000000-0000-0000-0000-000000000003', 'melod:query'),
    ('00000000-0000-0000-0000-000000000003', 'melod:summarize'),
    ('00000000-0000-0000-0000-000000000003', 'cases:view'),
    ('00000000-0000-0000-0000-000000000003', 'notifications:view'),
    ('00000000-0000-0000-0000-000000000003', 'notebooks:view')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- GROUP ROLES (001) — Everyone group gets the ReadOnly role baseline
-- ============================================================================

INSERT INTO group_roles (group_id, role_id) VALUES
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000003')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- NAMESPACES (054) — default namespace for unscoped resources
-- ============================================================================

INSERT INTO namespaces (id, name, description, provider) VALUES
    ('00000000-0000-0000-0000-000000000000', 'default', 'Default namespace for unscoped resources', 'default')
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- SETTINGS SINGLETONS — 001 (system/prevalence), 062 (signal processor),
-- 133 (license_status). melod_settings moved to enterprise overlay.
-- ============================================================================

INSERT INTO system_settings (id) VALUES ('default') ON CONFLICT (id) DO NOTHING;
INSERT INTO prevalence_settings (id) VALUES ('default') ON CONFLICT (id) DO NOTHING;
INSERT INTO signal_processor_watermarks (id) VALUES ('default') ON CONFLICT (id) DO NOTHING;

-- license_status is a singleton; WHERE NOT EXISTS is clearer than relying on
-- the table's id-default + unique behavior to make ON CONFLICT meaningful.
INSERT INTO license_status (status, valid)
SELECT 'active', TRUE WHERE NOT EXISTS (SELECT 1 FROM license_status);

-- ============================================================================
-- SYSTEM USERS (078) — AI investigation system user
-- ============================================================================

INSERT INTO users (id, email, name, password_hash, status) VALUES
    ('00000000-0000-0000-0000-000000000099', 'system-ai@nanosiem.local', 'NanoSIEM AI', '', 'system')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ENRICHMENT SOURCES — 001 (ipinfo_lite), 031 (threatfox), 057 (tor_exit_nodes)
-- ============================================================================

INSERT INTO enrichment_sources (id, name, source_type, description, enabled) VALUES
    ('ipinfo_lite', 'IPinfo Lite', 'ipinfo_lite',
     'Free IP geolocation and ASN data from IPinfo. Provides country, continent, and ASN information for IP addresses.',
     false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO enrichment_sources (id, name, source_type, description, enabled, config) VALUES
    ('threatfox', 'ThreatFox', 'ioc_feed',
     'Free IOC database from abuse.ch providing malware and botnet indicators including IPs, domains, URLs, and file hashes.',
     false,
     '{
         "sync_interval_hours": 6,
         "auto_sync_enabled": false,
         "ttl_days": 7,
         "api_endpoint": "https://threatfox-api.abuse.ch/api/v1/",
         "ioc_query_days": 7
     }'::jsonb)
ON CONFLICT (id) DO NOTHING;

INSERT INTO enrichment_sources (id, name, source_type, description, enabled, config) VALUES
    ('tor_exit_nodes', 'TOR Exit Nodes', 'ioc_feed',
     'TOR network exit node IPs from the official Tor Project Onionoo API. Useful for detecting anonymized traffic in enterprise networks.',
     false,
     '{
         "sync_interval_hours": 6,
         "auto_sync_enabled": false,
         "ttl_days": 1,
         "confidence_level": 85,
         "timeout_secs": 120,
         "api_endpoint": "https://onionoo.torproject.org/details?type=relay&flag=Exit"
     }'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SOURCE CONFIGURATIONS (047) — HTTP / Vector / Kafka / S3 / GCP PubSub /
-- Splunk HEC. Includes the default routing rules for HTTP + Vector.
-- ============================================================================

INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed, deployed_at) VALUES
    ('30000000-0000-0000-0000-000000000001', 'HTTP Ingestion',
     'Receives events via HTTP POST with X-Source-Type header. System-level source always enabled.',
     'http',
     '{"address": "0.0.0.0:8080", "path": "/ingest", "auth": "token"}'::jsonb,
     true, true, NOW())
ON CONFLICT (name) DO NOTHING;

INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed, deployed_at) VALUES
    ('30000000-0000-0000-0000-000000000002', 'Vector Ingestion',
     'Receives events from upstream Vector instances (aggregators, forwarders). Port 6000 is the standard Vector-to-Vector port.',
     'vector',
     '{"address": "0.0.0.0:6000", "version": "2", "acknowledgements": true}'::jsonb,
     true, true, NOW())
ON CONFLICT (name) DO NOTHING;

INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed) VALUES
    ('30000000-0000-0000-0000-000000000003', 'Kafka',
     'Consume logs from Apache Kafka topics. Configure bootstrap servers and topics, then add routing rules based on topic names.',
     'kafka',
     '{"bootstrap_servers": "", "topics": [], "group_id": "nanosiem", "auto_offset_reset": "latest"}'::jsonb,
     false, false)
ON CONFLICT (name) DO NOTHING;

INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed) VALUES
    ('30000000-0000-0000-0000-000000000004', 'AWS S3',
     'Ingest logs from AWS S3 via SQS notifications. Configure your SQS queue URL and add routing rules based on bucket or key patterns.',
     'aws_s3',
     '{"sqs_queue_url": "", "region": "us-east-1", "compression": "auto"}'::jsonb,
     false, false)
ON CONFLICT (name) DO NOTHING;

INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed) VALUES
    ('30000000-0000-0000-0000-000000000005', 'GCP Pub/Sub',
     'Subscribe to Google Cloud Pub/Sub topics. Configure your project and subscription, then add routing rules based on message attributes.',
     'gcp_pubsub',
     '{"project": "", "subscription": "", "ack_deadline_secs": 60}'::jsonb,
     false, false)
ON CONFLICT (name) DO NOTHING;

INSERT INTO source_configurations (id, name, description, config_type, connection_config, enabled, deployed) VALUES
    ('30000000-0000-0000-0000-000000000006', 'Splunk HEC',
     'Receive logs via Splunk HTTP Event Collector protocol. Configure tokens and add routing rules based on sourcetype.',
     'splunk_hec',
     '{"address": "0.0.0.0:8088", "valid_tokens": []}'::jsonb,
     false, false)
ON CONFLICT (name) DO NOTHING;

INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type)
SELECT '30000000-0000-0000-0000-000000000001'::uuid, priority, 'source_type', match_type, match_value, target_source_type
FROM (VALUES
    (10, 'exact', 'apache', 'apache'),
    (11, 'exact', 'apache_access', 'apache'),
    (12, 'exact', 'apache_error', 'apache'),
    (20, 'exact', 'json', 'json_generic'),
    (21, 'exact', 'json_generic', 'json_generic'),
    (30, 'exact', 'squid', 'squid_proxy'),
    (31, 'exact', 'squid_proxy', 'squid_proxy'),
    (40, 'exact', 'sysmon', 'sysmon'),
    (41, 'exact', 'windows_sysmon', 'sysmon'),
    (1000, 'default', NULL, 'unknown')
) AS rules(priority, match_type, match_value, target_source_type)
WHERE EXISTS (SELECT 1 FROM source_configurations WHERE id = '30000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type)
SELECT '30000000-0000-0000-0000-000000000002'::uuid, 1000, 'source_type', 'default', NULL, '${source_type}'
WHERE EXISTS (SELECT 1 FROM source_configurations WHERE id = '30000000-0000-0000-0000-000000000002')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- MARKETPLACE CATALOG (101) — built-in entries for the enrichment +
-- identity-provider catalogue
-- ============================================================================

INSERT INTO marketplace_catalog (slug, name, description, category, icon, author, source_type, execution_backend, native_source_id, installed, requires_credential, credential_fields, config, enabled) VALUES
    ('ipinfo_lite', 'IPinfo Lite',
     'Free IP geolocation and ASN enrichment via IPinfo.io lite databases',
     'data', 'map-pin', 'nano', 'system', 'native', 'ipinfo_lite', true, 'optional',
     '[{"name": "download_url", "label": "Download URL", "field_type": "secret", "required": false, "help": "IPinfo Lite CSV download URL with token. Get it from https://ipinfo.io/account/data-downloads"}]',
     '{}', true)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO marketplace_catalog (slug, name, description, category, icon, author, source_type, execution_backend, identity_provider_id, installed, requires_credential, credential_fields, config, enabled) VALUES
    ('entra-id', 'Microsoft Entra ID',
     'Sync users and groups from Microsoft Entra ID (Azure AD) via MS Graph API',
     'identity', 'users', 'nano', 'system', 'identity', 'entra_id', false, 'required',
     '[{"name": "tenant_id", "label": "Tenant ID", "field_type": "text", "required": true, "help": "Azure AD tenant ID"},
       {"name": "client_id", "label": "Client ID", "field_type": "text", "required": true, "help": "App registration client ID"},
       {"name": "client_secret", "label": "Client Secret", "field_type": "secret", "required": true, "help": "App registration client secret"}]',
     '{"color": "blue"}', false),
    ('google-workspace', 'Google Workspace',
     'Sync users from Google Workspace via Admin SDK',
     'identity', 'users', 'nano', 'system', 'identity', 'google_workspace', false, 'required',
     '[{"name": "service_account_json", "label": "Service Account JSON", "field_type": "secret", "required": true, "help": "Google service account key JSON"},
       {"name": "admin_email", "label": "Admin Email", "field_type": "text", "required": true, "help": "Workspace admin email for domain-wide delegation"},
       {"name": "domain", "label": "Domain", "field_type": "text", "required": true, "help": "Google Workspace domain (e.g. example.com)"}]',
     '{"color": "green"}', false),
    ('okta', 'Okta',
     'Sync users from Okta via Users API',
     'identity', 'users', 'nano', 'system', 'identity', 'okta', false, 'required',
     '[{"name": "domain", "label": "Okta Domain", "field_type": "text", "required": true, "help": "Okta org domain (e.g. dev-12345.okta.com)"},
       {"name": "api_token", "label": "API Token", "field_type": "secret", "required": true, "help": "SSWS API token from Okta admin console"}]',
     '{"color": "blue"}', false),
    ('workday', 'Workday',
     'Sync users from Workday via RaaS (Report as a Service)',
     'identity', 'users', 'nano', 'system', 'identity', 'workday', false, 'required',
     '[{"name": "report_url", "label": "Report URL", "field_type": "text", "required": true, "help": "Published RaaS report URL"},
       {"name": "username", "label": "ISU Username", "field_type": "text", "required": true, "help": "Integration System User username"},
       {"name": "password", "label": "ISU Password", "field_type": "secret", "required": true, "help": "Integration System User password"}]',
     '{"color": "orange"}', false),
    ('active-directory', 'Active Directory',
     'Push-based user sync from on-prem Active Directory via collector script',
     'identity', 'users', 'nano', 'system', 'identity', 'active_directory', false, 'required',
     '[{"name": "collector_token", "label": "Collector Token", "field_type": "secret", "required": true, "help": "Token for the AD collector script to authenticate"}]',
     '{"color": "cyan"}', false)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO enrichment_marketplace_repos (name, slug, description, url, branch, enrichments_path, auto_sync_enabled, sync_interval_hours, enabled) VALUES
    ('nano Enrichments', 'nano-enrichments',
     'Official enrichment catalog — threat intel feeds, agent lookups, and identity providers',
     'https://github.com/nanos-sh/nano-enrichments', 'main', 'enrichments/',
     true, 12, true)
ON CONFLICT (slug) DO NOTHING;

-- ============================================================================
-- PROVIDER CREDENTIALS (142) — Workers AI provider stub
-- ============================================================================

INSERT INTO provider_credentials (provider, display_name, config, enabled) VALUES
    ('workers-ai', 'Workers AI', '{}', false)
ON CONFLICT (provider) DO NOTHING;
