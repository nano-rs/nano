-- Enrichment Marketplace
-- Unifies data enrichments, agent enrichments, custom enrichments, and identity
-- providers into a single browsable catalog with GitHub repository sync support.

-- =============================================================================
-- Enrichment Marketplace Repos
-- =============================================================================
-- External GitHub repos containing enrichment manifests + code.
-- Follows the same pattern as rule_repositories.

CREATE TABLE IF NOT EXISTS enrichment_marketplace_repos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    slug VARCHAR(200) NOT NULL UNIQUE,
    description TEXT,
    url VARCHAR(500) NOT NULL,
    branch VARCHAR(100) DEFAULT 'main',
    enrichments_path VARCHAR(200) DEFAULT 'enrichments/',
    auto_sync_enabled BOOLEAN DEFAULT false,
    sync_interval_hours INTEGER DEFAULT 24,
    last_synced_at TIMESTAMPTZ,
    last_sync_commit VARCHAR(100),
    last_sync_status VARCHAR(20),
    last_sync_error TEXT,
    enrichment_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION update_enrichment_marketplace_repos_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_enrichment_marketplace_repos_updated_at
    BEFORE UPDATE ON enrichment_marketplace_repos
    FOR EACH ROW
    EXECUTE FUNCTION update_enrichment_marketplace_repos_updated_at();

CREATE INDEX IF NOT EXISTS idx_enrichment_marketplace_repos_enabled
    ON enrichment_marketplace_repos(enabled) WHERE enabled = true;

COMMENT ON TABLE enrichment_marketplace_repos IS 'External GitHub repositories containing enrichment manifests and code';

-- =============================================================================
-- Marketplace Catalog
-- =============================================================================
-- Unified catalog of all enrichment types: data feeds, agent lookups, identity
-- providers. Each entry can come from system defaults, external repos, or custom
-- user creation.

CREATE TABLE IF NOT EXISTS marketplace_catalog (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    -- Category: data (bulk feeds), agent (on-demand lookups), identity (user sync)
    category VARCHAR(20) NOT NULL CHECK (category IN ('data', 'agent', 'identity')),
    tags TEXT[] DEFAULT '{}',
    icon VARCHAR(50),
    author VARCHAR(100),

    -- Source tracking
    source_type VARCHAR(20) NOT NULL CHECK (source_type IN ('system', 'repository', 'custom')),
    repository_id UUID REFERENCES enrichment_marketplace_repos(id) ON DELETE SET NULL,
    repository_file_path VARCHAR(500),
    manifest_version INTEGER DEFAULT 1,

    -- Execution backend
    execution_backend VARCHAR(20) NOT NULL CHECK (execution_backend IN ('deno', 'native', 'identity')),

    -- Links to underlying subsystem tables (only one should be non-null)
    custom_enrichment_id UUID REFERENCES custom_enrichments(id) ON DELETE SET NULL,
    native_source_id VARCHAR(50),       -- enrichment_sources.id or agent_enrichment_providers.id
    identity_provider_id VARCHAR(50),   -- identity_providers.id

    -- Install state
    installed BOOLEAN DEFAULT false,
    installed_at TIMESTAMPTZ,
    installed_version INTEGER,

    -- Credentials (self-contained, matches agent_enrichment_providers pattern)
    requires_credential VARCHAR(20) DEFAULT 'none' CHECK (requires_credential IN ('none', 'optional', 'required')),
    credential_fields JSONB DEFAULT '[]',        -- UI field definitions [{name, label, field_type, required, help}]
    credentials_encrypted BYTEA,                 -- AES-256-GCM encrypted JSON of user-provided credentials
    credentials_nonce VARCHAR(32),               -- Base64 nonce for decryption

    -- Code (for deno backend)
    code TEXT,
    allowed_domains TEXT[] DEFAULT '{}',
    config JSONB DEFAULT '{}',

    -- Status
    enabled BOOLEAN DEFAULT false,
    last_sync_at TIMESTAMPTZ,
    last_sync_status VARCHAR(20),
    last_error TEXT,
    record_count BIGINT DEFAULT 0,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION update_marketplace_catalog_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_marketplace_catalog_updated_at
    BEFORE UPDATE ON marketplace_catalog
    FOR EACH ROW
    EXECUTE FUNCTION update_marketplace_catalog_updated_at();

CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_category ON marketplace_catalog(category);
CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_source_type ON marketplace_catalog(source_type);
CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_installed ON marketplace_catalog(installed) WHERE installed = true;
CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_enabled ON marketplace_catalog(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_repository ON marketplace_catalog(repository_id) WHERE repository_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_native_source ON marketplace_catalog(native_source_id) WHERE native_source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_custom_enrichment ON marketplace_catalog(custom_enrichment_id) WHERE custom_enrichment_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_marketplace_catalog_identity_provider ON marketplace_catalog(identity_provider_id) WHERE identity_provider_id IS NOT NULL;

COMMENT ON TABLE marketplace_catalog IS 'Unified enrichment marketplace: data feeds, agent lookups, identity providers';
COMMENT ON COLUMN marketplace_catalog.native_source_id IS 'FK to enrichment_sources.id or agent_enrichment_providers.id (text PK tables)';
COMMENT ON COLUMN marketplace_catalog.execution_backend IS 'deno = TypeScript sandbox, native = built-in Rust, identity = IdP sync';

-- =============================================================================
-- Seed IPinfo Lite (native backend — not Deno, stays built-in)
-- =============================================================================

INSERT INTO marketplace_catalog (slug, name, description, category, icon, author, source_type, execution_backend, native_source_id, installed, requires_credential, credential_fields, config, enabled)
VALUES (
    'ipinfo_lite',
    'IPinfo Lite',
    'Free IP geolocation and ASN enrichment via IPinfo.io lite databases',
    'data',
    'map-pin',
    'nano',
    'system',
    'native',
    'ipinfo_lite',
    true,
    'optional',
    '[{"name": "download_url", "label": "Download URL", "field_type": "secret", "required": false, "help": "IPinfo Lite CSV download URL with token. Get it from https://ipinfo.io/account/data-downloads"}]',
    '{}',
    true
) ON CONFLICT (slug) DO NOTHING;

-- Identity providers (native — credentials stored in identity_providers table)
INSERT INTO marketplace_catalog (slug, name, description, category, icon, author, source_type, execution_backend, identity_provider_id, installed, requires_credential, credential_fields, config, enabled)
VALUES
(
    'entra-id',
    'Microsoft Entra ID',
    'Sync users and groups from Microsoft Entra ID (Azure AD) via MS Graph API',
    'identity',
    'users',
    'nano',
    'system',
    'identity',
    'entra_id',
    false,
    'required',
    '[{"name": "tenant_id", "label": "Tenant ID", "field_type": "text", "required": true, "help": "Azure AD tenant ID"},
      {"name": "client_id", "label": "Client ID", "field_type": "text", "required": true, "help": "App registration client ID"},
      {"name": "client_secret", "label": "Client Secret", "field_type": "secret", "required": true, "help": "App registration client secret"}]',
    '{"color": "blue"}',
    false
),
(
    'google-workspace',
    'Google Workspace',
    'Sync users from Google Workspace via Admin SDK',
    'identity',
    'users',
    'nano',
    'system',
    'identity',
    'google_workspace',
    false,
    'required',
    '[{"name": "service_account_json", "label": "Service Account JSON", "field_type": "secret", "required": true, "help": "Google service account key JSON"},
      {"name": "admin_email", "label": "Admin Email", "field_type": "text", "required": true, "help": "Workspace admin email for domain-wide delegation"},
      {"name": "domain", "label": "Domain", "field_type": "text", "required": true, "help": "Google Workspace domain (e.g. example.com)"}]',
    '{"color": "green"}',
    false
),
(
    'okta',
    'Okta',
    'Sync users from Okta via Users API',
    'identity',
    'users',
    'nano',
    'system',
    'identity',
    'okta',
    false,
    'required',
    '[{"name": "domain", "label": "Okta Domain", "field_type": "text", "required": true, "help": "Okta org domain (e.g. dev-12345.okta.com)"},
      {"name": "api_token", "label": "API Token", "field_type": "secret", "required": true, "help": "SSWS API token from Okta admin console"}]',
    '{"color": "blue"}',
    false
),
(
    'workday',
    'Workday',
    'Sync users from Workday via RaaS (Report as a Service)',
    'identity',
    'users',
    'nano',
    'system',
    'identity',
    'workday',
    false,
    'required',
    '[{"name": "report_url", "label": "Report URL", "field_type": "text", "required": true, "help": "Published RaaS report URL"},
      {"name": "username", "label": "ISU Username", "field_type": "text", "required": true, "help": "Integration System User username"},
      {"name": "password", "label": "ISU Password", "field_type": "secret", "required": true, "help": "Integration System User password"}]',
    '{"color": "orange"}',
    false
),
(
    'active-directory',
    'Active Directory',
    'Push-based user sync from on-prem Active Directory via collector script',
    'identity',
    'users',
    'nano',
    'system',
    'identity',
    'active_directory',
    false,
    'required',
    '[{"name": "collector_token", "label": "Collector Token", "field_type": "secret", "required": true, "help": "Token for the AD collector script to authenticate"}]',
    '{"color": "cyan"}',
    false
)
ON CONFLICT (slug) DO NOTHING;

-- =============================================================================
-- Seed default enrichment repository
-- =============================================================================
-- Community enrichments repo — sync this to populate the catalog with
-- AbuseIPDB, Shodan, GreyNoise, OTX, URLhaus, MalwareBazaar, ThreatFox, etc.

INSERT INTO enrichment_marketplace_repos (
    name, slug, description, url, branch, enrichments_path,
    auto_sync_enabled, sync_interval_hours, enabled
) VALUES (
    'nano Enrichments',
    'nano-enrichments',
    'Official enrichment catalog — threat intel feeds, agent lookups, and identity providers',
    'https://github.com/nanos-sh/nano-enrichments',
    'main',
    'enrichments/',
    true,
    12,
    true
) ON CONFLICT (slug) DO NOTHING;

-- Changelog for update notifications
ALTER TABLE marketplace_catalog ADD COLUMN IF NOT EXISTS changelog TEXT;
