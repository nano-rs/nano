-- NAN-2361: dormant tenant/auth substrate for DEPLOYMENT_MODE=enterprise_shared.
--
-- These tables are additive and are not consulted by self-hosted, managed, or
-- demo deployments. The fixed default tenant backfill preserves the existing
-- single-deployment identity when an operator deliberately migrates an
-- existing database into enterprise_shared; it does not activate shared
-- behavior by itself.

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'deleted')),
    tokens_valid_from TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT tenants_slug_shape CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$')
);

CREATE TABLE IF NOT EXISTS tenant_members (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),
    tokens_valid_from TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS tenant_member_roles (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, role_id),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES tenant_members(tenant_id, user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_members_user_active
    ON tenant_members (user_id, tenant_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_tenant_member_roles_user
    ON tenant_member_roles (user_id, tenant_id, role_id);

-- Restricted-source grants are tenant+role authority in shared mode. Do not
-- reuse the dedicated group_roles -> source_type_grants graph: those groups
-- are deployment-global, so the same role in two tenants could otherwise
-- inherit a grant configured for only one tenant.
CREATE TABLE IF NOT EXISTS tenant_role_source_type_grants (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    source_type VARCHAR(100) NOT NULL
        REFERENCES restricted_source_types(source_type) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, role_id, source_type)
);

CREATE INDEX IF NOT EXISTS idx_tenant_role_source_type_grants_role
    ON tenant_role_source_type_grants (tenant_id, role_id);

-- Tenant-local role membership contributes to the same monotonic authority
-- generation consumed by TenantMembershipResolver and SourceScopeResolver.
-- Without this trigger a role revoke could reuse a cached `(tenant,user)`
-- source scope until its ordinary TTL elapsed.
DROP TRIGGER IF EXISTS bump_grant_authority_tenant_member_roles
    ON tenant_member_roles;
CREATE TRIGGER bump_grant_authority_tenant_member_roles
AFTER INSERT OR UPDATE OR DELETE ON tenant_member_roles
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_tenant_role_source_type_grants
    ON tenant_role_source_type_grants;
CREATE TRIGGER bump_grant_authority_tenant_role_source_type_grants
AFTER INSERT OR UPDATE OR DELETE ON tenant_role_source_type_grants
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

-- Stable compatibility identity for an existing dedicated database.
INSERT INTO tenants (id, slug, display_name, status)
VALUES (
    '00000000-0000-0000-0000-000000000100'::uuid,
    'default',
    'Default tenant',
    'active'
)
ON CONFLICT DO NOTHING;

INSERT INTO tenant_members (tenant_id, user_id, status)
SELECT '00000000-0000-0000-0000-000000000100'::uuid, u.id, 'active'
FROM users u
ON CONFLICT (tenant_id, user_id) DO NOTHING;

-- Preserve each existing user's effective role set inside the compatibility
-- tenant. Permissions remain derived from role_permissions at request time.
INSERT INTO tenant_member_roles (tenant_id, user_id, role_id)
SELECT DISTINCT
    '00000000-0000-0000-0000-000000000100'::uuid,
    ug.user_id,
    gr.role_id
FROM user_groups ug
JOIN group_roles gr ON gr.group_id = ug.group_id
ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS tenant_id UUID,
    ADD COLUMN IF NOT EXISTS authenticated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mfa_authenticated_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'sessions_tenant_membership_fkey'
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT sessions_tenant_membership_fkey
            FOREIGN KEY (tenant_id, user_id)
            REFERENCES tenant_members(tenant_id, user_id)
            ON DELETE CASCADE;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'sessions_shared_authentication_time_check'
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT sessions_shared_authentication_time_check
            CHECK (
                tenant_id IS NULL
                OR (
                    authenticated_at IS NOT NULL
                    AND (mfa_authenticated_at IS NULL
                         OR mfa_authenticated_at >= authenticated_at - INTERVAL '30 seconds')
                )
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user_active
    ON sessions (tenant_id, user_id, expires_at DESC)
    WHERE tenant_id IS NOT NULL;

COMMENT ON TABLE tenants IS
    'Dormant unless DEPLOYMENT_MODE=enterprise_shared. Server-authoritative tenant registry.';
COMMENT ON TABLE tenant_members IS
    'Server-authoritative user membership and revocation boundary for enterprise_shared.';
COMMENT ON TABLE tenant_member_roles IS
    'Tenant-local role assignment; never inferred from a client tenant selector.';
COMMENT ON TABLE tenant_role_source_type_grants IS
    'Exact enterprise_shared tenant+role restricted-source grants; global groups are never shared-mode authority.';
COMMENT ON COLUMN sessions.tenant_id IS
    'Required by enterprise_shared issuance; NULL preserves legacy dedicated/demo sessions.';
COMMENT ON COLUMN sessions.authenticated_at IS
    'Immutable interactive authentication time for enterprise_shared sessions; refresh never advances it.';
COMMENT ON COLUMN sessions.mfa_authenticated_at IS
    'Immutable local-MFA completion time for enterprise_shared sessions; NULL for non-local-MFA authentication.';
