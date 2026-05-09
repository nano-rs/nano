-- Authentication and RBAC Schema
-- Requirements: 4.1, 4.2, 4.3, 4.4, 5.1, 6.7

-- ============================================================================
-- PERMISSIONS TABLE (reference data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL
);

-- ============================================================================
-- ROLES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- ROLE-PERMISSION MAPPING
-- ============================================================================
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ============================================================================
-- GROUPS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- GROUP-ROLE MAPPING
-- ============================================================================
CREATE TABLE IF NOT EXISTS group_roles (
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

-- ============================================================================
-- OIDC PROVIDERS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS oidc_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(50) UNIQUE NOT NULL,
    issuer VARCHAR(500) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted BYTEA NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email'],
    group_claim VARCHAR(100) DEFAULT 'groups',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMPTZ,
    oidc_provider_id UUID REFERENCES oidc_providers(id) ON DELETE SET NULL,
    oidc_subject VARCHAR(255),
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- USER-GROUP MAPPING
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_groups (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- ============================================================================
-- OIDC GROUP MAPPINGS
-- ============================================================================
CREATE TABLE IF NOT EXISTS oidc_group_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    oidc_group VARCHAR(255) NOT NULL,
    local_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    UNIQUE (provider_id, oidc_group)
);

-- ============================================================================
-- SESSIONS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- API KEYS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL,
    permissions TEXT[] NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    rate_limit INT,
    last_used_at TIMESTAMPTZ,
    last_used_ip VARCHAR(45),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- AUDIT LOGS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE
);

-- ============================================================================
-- SYSTEM CONFIG TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================================
-- INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_oidc ON users(oidc_provider_id, oidc_subject);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

-- ============================================================================
-- SEED PERMISSIONS
-- ============================================================================
INSERT INTO permissions (id, name, description, category) VALUES
    -- Search permissions
    ('search:view', 'View Search', 'Access the search interface', 'search'),
    ('search:execute', 'Execute Search', 'Run search queries', 'search'),
    ('search:save', 'Save Search', 'Save search queries', 'search'),
    ('search:share', 'Share Search', 'Share search queries with others', 'search'),
    
    -- Dashboard permissions
    ('dashboards:view', 'View Dashboards', 'View dashboards', 'dashboards'),
    ('dashboards:create', 'Create Dashboards', 'Create new dashboards', 'dashboards'),
    ('dashboards:edit', 'Edit Dashboards', 'Modify existing dashboards', 'dashboards'),
    ('dashboards:delete', 'Delete Dashboards', 'Delete dashboards', 'dashboards'),
    
    -- Detection permissions
    ('detections:view', 'View Detections', 'View detection rules', 'detections'),
    ('detections:create', 'Create Detections', 'Create new detection rules', 'detections'),
    ('detections:edit', 'Edit Detections', 'Modify detection rules', 'detections'),
    ('detections:delete', 'Delete Detections', 'Delete detection rules', 'detections'),
    ('detections:enable', 'Enable/Disable Detections', 'Enable or disable detection rules', 'detections'),
    ('detections:promote', 'Promote/Demote Detections', 'Change detection rule mode', 'detections'),
    
    -- Alert permissions
    ('alerts:view', 'View Alerts', 'View alerts', 'alerts'),
    ('alerts:acknowledge', 'Acknowledge Alerts', 'Acknowledge alerts', 'alerts'),
    ('alerts:close', 'Close Alerts', 'Close alerts', 'alerts'),
    ('alerts:assign', 'Assign Alerts', 'Assign alerts to users', 'alerts'),
    
    -- Parser permissions
    ('parsers:view', 'View Parsers', 'View parser configurations', 'parsers'),
    ('parsers:create', 'Create Parsers', 'Create new parsers', 'parsers'),
    ('parsers:edit', 'Edit Parsers', 'Modify parser configurations', 'parsers'),
    ('parsers:delete', 'Delete Parsers', 'Delete parsers', 'parsers'),
    ('parsers:deploy', 'Deploy Parsers', 'Deploy parsers to Vector', 'parsers'),
    
    -- Feed permissions
    ('feeds:view', 'View Feeds', 'View data feeds', 'feeds'),
    ('feeds:create', 'Create Feeds', 'Create new feeds', 'feeds'),
    ('feeds:edit', 'Edit Feeds', 'Modify feed configurations', 'feeds'),
    ('feeds:delete', 'Delete Feeds', 'Delete feeds', 'feeds'),
    
    -- Enrichment permissions
    ('enrichments:view', 'View Enrichments', 'View enrichment sources', 'enrichments'),
    ('enrichments:configure', 'Configure Enrichments', 'Configure enrichment sources', 'enrichments'),
    
    -- Lookup table permissions
    ('lookup:view', 'View Lookup Tables', 'View lookup tables', 'lookup'),
    ('lookup:create', 'Create Lookup Tables', 'Create lookup tables', 'lookup'),
    ('lookup:edit', 'Edit Lookup Tables', 'Modify lookup tables', 'lookup'),
    ('lookup:delete', 'Delete Lookup Tables', 'Delete lookup tables', 'lookup'),
    
    -- Risk analytics permissions
    ('risk:view', 'View Risk Analytics', 'View risk scores and analytics', 'risk'),
    ('risk:configure', 'Configure Risk', 'Configure risk scoring settings', 'risk'),
    ('risk:clear', 'Clear Risk Scores', 'Clear entity risk scores', 'risk'),
    
    -- Settings permissions
    ('settings:view', 'View Settings', 'View system settings', 'settings'),
    ('settings:system', 'System Settings', 'Modify system settings', 'settings'),
    ('settings:retention', 'Retention Settings', 'Modify data retention settings', 'settings'),
    ('settings:ai', 'AI Settings', 'Modify AI/meloD settings', 'settings'),
    ('settings:risk', 'Risk Settings', 'Modify risk scoring settings', 'settings'),
    
    -- User management permissions
    ('users:view', 'View Users', 'View user accounts', 'users'),
    ('users:create', 'Create Users', 'Create user accounts', 'users'),
    ('users:edit', 'Edit Users', 'Modify user accounts', 'users'),
    ('users:delete', 'Delete Users', 'Delete user accounts', 'users'),
    
    -- Group management permissions
    ('groups:view', 'View Groups', 'View groups', 'groups'),
    ('groups:create', 'Create Groups', 'Create groups', 'groups'),
    ('groups:edit', 'Edit Groups', 'Modify groups', 'groups'),
    ('groups:delete', 'Delete Groups', 'Delete groups', 'groups'),
    
    -- Role management permissions
    ('roles:view', 'View Roles', 'View roles', 'roles'),
    ('roles:create', 'Create Roles', 'Create roles', 'roles'),
    ('roles:edit', 'Edit Roles', 'Modify roles', 'roles'),
    ('roles:delete', 'Delete Roles', 'Delete roles', 'roles'),
    
    -- API key permissions
    ('apikeys:view', 'View API Keys', 'View API keys', 'apikeys'),
    ('apikeys:create', 'Create API Keys', 'Create API keys', 'apikeys'),
    ('apikeys:delete', 'Delete API Keys', 'Delete API keys', 'apikeys'),
    
    -- Audit permissions
    ('audit:view', 'View Audit Logs', 'View audit logs', 'audit')
ON CONFLICT (id) DO NOTHING;


-- ============================================================================
-- SEED BUILT-IN ROLES
-- ============================================================================

-- Admin role (all permissions)
INSERT INTO roles (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Admin', 'Full system access with all permissions', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Editor role (detection engineers)
INSERT INTO roles (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000002', 'Editor', 'Create and manage detections, parsers, and dashboards', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ReadOnly role (analysts)
INSERT INTO roles (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000003', 'ReadOnly', 'View-only access for search and monitoring', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- ASSIGN PERMISSIONS TO ADMIN ROLE (all permissions)
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id FROM permissions
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ASSIGN PERMISSIONS TO EDITOR ROLE
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    -- Search (all)
    ('00000000-0000-0000-0000-000000000002', 'search:view'),
    ('00000000-0000-0000-0000-000000000002', 'search:execute'),
    ('00000000-0000-0000-0000-000000000002', 'search:save'),
    ('00000000-0000-0000-0000-000000000002', 'search:share'),
    -- Dashboards (all)
    ('00000000-0000-0000-0000-000000000002', 'dashboards:view'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:create'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:edit'),
    ('00000000-0000-0000-0000-000000000002', 'dashboards:delete'),
    -- Detections (all)
    ('00000000-0000-0000-0000-000000000002', 'detections:view'),
    ('00000000-0000-0000-0000-000000000002', 'detections:create'),
    ('00000000-0000-0000-0000-000000000002', 'detections:edit'),
    ('00000000-0000-0000-0000-000000000002', 'detections:delete'),
    ('00000000-0000-0000-0000-000000000002', 'detections:enable'),
    ('00000000-0000-0000-0000-000000000002', 'detections:promote'),
    -- Alerts (view, acknowledge, close)
    ('00000000-0000-0000-0000-000000000002', 'alerts:view'),
    ('00000000-0000-0000-0000-000000000002', 'alerts:acknowledge'),
    ('00000000-0000-0000-0000-000000000002', 'alerts:close'),
    -- Parsers (all)
    ('00000000-0000-0000-0000-000000000002', 'parsers:view'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:create'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:edit'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:delete'),
    ('00000000-0000-0000-0000-000000000002', 'parsers:deploy'),
    -- Feeds (all)
    ('00000000-0000-0000-0000-000000000002', 'feeds:view'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:create'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:edit'),
    ('00000000-0000-0000-0000-000000000002', 'feeds:delete'),
    -- Enrichments (view only)
    ('00000000-0000-0000-0000-000000000002', 'enrichments:view'),
    -- Lookup tables (all)
    ('00000000-0000-0000-0000-000000000002', 'lookup:view'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:create'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:edit'),
    ('00000000-0000-0000-0000-000000000002', 'lookup:delete'),
    -- Risk (view only)
    ('00000000-0000-0000-0000-000000000002', 'risk:view'),
    -- Settings (view only)
    ('00000000-0000-0000-0000-000000000002', 'settings:view')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ASSIGN PERMISSIONS TO READONLY ROLE
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    -- Search (view and execute)
    ('00000000-0000-0000-0000-000000000003', 'search:view'),
    ('00000000-0000-0000-0000-000000000003', 'search:execute'),
    -- Dashboards (view only)
    ('00000000-0000-0000-0000-000000000003', 'dashboards:view'),
    -- Detections (view only)
    ('00000000-0000-0000-0000-000000000003', 'detections:view'),
    -- Alerts (view only)
    ('00000000-0000-0000-0000-000000000003', 'alerts:view'),
    -- Parsers (view only)
    ('00000000-0000-0000-0000-000000000003', 'parsers:view'),
    -- Feeds (view only)
    ('00000000-0000-0000-0000-000000000003', 'feeds:view'),
    -- Enrichments (view only)
    ('00000000-0000-0000-0000-000000000003', 'enrichments:view'),
    -- Lookup tables (view only)
    ('00000000-0000-0000-0000-000000000003', 'lookup:view'),
    -- Risk (view only)
    ('00000000-0000-0000-0000-000000000003', 'risk:view')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- CREATE DEFAULT "EVERYONE" GROUP
-- ============================================================================
INSERT INTO groups (id, name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Everyone', 'Default group that all users belong to', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- TRIGGER TO AUTO-ADD USERS TO EVERYONE GROUP
-- ============================================================================
CREATE OR REPLACE FUNCTION add_user_to_everyone_group()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO user_groups (user_id, group_id)
    VALUES (NEW.id, '00000000-0000-0000-0000-000000000001')
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_add_user_to_everyone ON users;
CREATE TRIGGER trigger_add_user_to_everyone
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION add_user_to_everyone_group();

-- ============================================================================
-- TRIGGER TO UPDATE updated_at TIMESTAMPS
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_groups_updated_at ON groups;
CREATE TRIGGER trigger_groups_updated_at
    BEFORE UPDATE ON groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_roles_updated_at ON roles;
CREATE TRIGGER trigger_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_oidc_providers_updated_at ON oidc_providers;
CREATE TRIGGER trigger_oidc_providers_updated_at
    BEFORE UPDATE ON oidc_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
