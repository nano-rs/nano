-- Identity Provider Sync System
-- Stores configuration for identity providers (Entra ID, Google Workspace, Active Directory)
-- and a unified user registry of all synced user records.

-- =============================================================================
-- Identity Providers Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS identity_providers (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,  -- 'entra_id', 'google_workspace', 'active_directory'
    enabled BOOLEAN DEFAULT false,
    credentials_encrypted BYTEA,  -- AES-256-GCM encrypted provider credentials (JSON)
    config JSONB DEFAULT '{}',  -- Provider-specific config (sync_interval_hours, domain_filter, group_filter)
    sync_status VARCHAR(20) DEFAULT 'idle',  -- 'idle', 'in_progress', 'completed', 'failed'
    last_sync_at TIMESTAMPTZ,
    last_sync_error TEXT,
    last_sync_duration_ms BIGINT,
    user_count INTEGER DEFAULT 0,
    delta_link TEXT,  -- For incremental sync (MS Graph delta tokens, Google updatedMin)
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Trigger to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_identity_providers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_identity_providers_updated_at
    BEFORE UPDATE ON identity_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_identity_providers_updated_at();

CREATE INDEX IF NOT EXISTS idx_identity_providers_type ON identity_providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_identity_providers_enabled ON identity_providers(enabled) WHERE enabled = true;

COMMENT ON TABLE identity_providers IS 'Configuration for identity providers synced to the user registry';
COMMENT ON COLUMN identity_providers.credentials_encrypted IS 'AES-256-GCM encrypted credentials (tenant_id, client_id, client_secret, etc.)';
COMMENT ON COLUMN identity_providers.delta_link IS 'Opaque token for incremental/delta sync from the IdP';

-- =============================================================================
-- User Registry Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_registry (
    id BIGSERIAL PRIMARY KEY,
    provider_id VARCHAR(50) NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(256) NOT NULL,  -- IdP-native user ID

    -- Identity fields
    username VARCHAR(256),
    upn VARCHAR(256),  -- User Principal Name
    email VARCHAR(256),
    display_name VARCHAR(256),
    first_name VARCHAR(128),
    last_name VARCHAR(128),

    -- Organizational fields
    department VARCHAR(256),
    title VARCHAR(256),
    manager_upn VARCHAR(256),
    manager_display_name VARCHAR(256),
    company VARCHAR(256),
    office_location VARCHAR(256),
    city VARCHAR(128),
    country VARCHAR(128),

    -- Group membership (array of group names)
    groups TEXT[] DEFAULT '{}',

    -- Account status
    account_enabled BOOLEAN DEFAULT true,
    account_status VARCHAR(20) DEFAULT 'active',  -- 'active', 'disabled', 'suspended', 'deleted'

    -- Security fields
    mfa_enabled BOOLEAN,
    last_sign_in_at TIMESTAMPTZ,
    created_in_directory_at TIMESTAMPTZ,

    -- Extra fields
    phone VARCHAR(64),
    employee_id VARCHAR(128),
    employee_type VARCHAR(50) DEFAULT 'employee',  -- 'employee', 'contractor', 'guest', 'service_account'

    -- Sync metadata
    last_synced_at TIMESTAMPTZ DEFAULT NOW(),
    sync_hash VARCHAR(64),  -- SHA-256 of raw IdP record for change detection

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (provider_id, external_id)
);

-- Trigger to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_user_registry_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_user_registry_updated_at
    BEFORE UPDATE ON user_registry
    FOR EACH ROW
    EXECUTE FUNCTION update_user_registry_updated_at();

-- Indexes for lookups
CREATE INDEX IF NOT EXISTS idx_user_registry_username ON user_registry(lower(username));
CREATE INDEX IF NOT EXISTS idx_user_registry_upn ON user_registry(lower(upn));
CREATE INDEX IF NOT EXISTS idx_user_registry_email ON user_registry(lower(email));
CREATE INDEX IF NOT EXISTS idx_user_registry_provider ON user_registry(provider_id);
CREATE INDEX IF NOT EXISTS idx_user_registry_status ON user_registry(account_status);
CREATE INDEX IF NOT EXISTS idx_user_registry_updated ON user_registry(updated_at);

COMMENT ON TABLE user_registry IS 'Unified user directory from all identity providers';
COMMENT ON COLUMN user_registry.external_id IS 'The user ID as assigned by the identity provider';
COMMENT ON COLUMN user_registry.sync_hash IS 'SHA-256 of the raw IdP record; used to skip no-op updates';
