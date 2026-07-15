-- NAN-1841 / F-34: ADMIN full-visibility bypass for per-source RBAC.
--
-- Per-source RBAC (migration 244) has no admin / "view-all-sources" bypass:
--   denied = restricted_source_types − grants(user's groups)
-- so ANY source marked restricted WITHOUT a matching group grant is invisible to
-- EVERYONE, admins included. The F-34 change then made GET /api/cases/{id} return
-- 404 for a case whose alerts are ALL from denied sources — including for admins,
-- who must be able to see everything.
--
-- This permission is the positive, explicit bypass: a holder resolves to an empty
-- (unrestricted) source deny set in SourceScopeResolver::resolve, so they see
-- every source regardless of the restricted registry. It is DELIBERATELY separate
-- from `source_scopes:manage` (migration 244): administering the restriction
-- registry/grants must not silently also confer the right to READ every restricted
-- compartment. Granted to the Admin role only.

INSERT INTO permissions (id, name, description, category) VALUES
    (
        'source_scopes:view_all',
        'View All Sources (bypass restrictions)',
        'See every source_type regardless of the restricted-source registry — the admin/full-visibility bypass for per-source RBAC. Distinct from source_scopes:manage, which administers restrictions but does not itself grant data visibility.',
        'source_scopes'
    )
ON CONFLICT (id) DO NOTHING;

-- Grant to the Admin role only (00000000-0000-0000-0000-000000000001) — this
-- bypasses every source compartment, so it is admin-only by design.
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000001', 'source_scopes:view_all')
ON CONFLICT DO NOTHING;
