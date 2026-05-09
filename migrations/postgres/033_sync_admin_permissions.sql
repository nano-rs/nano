-- Migration: Sync Admin Role Permissions
--
-- This migration ensures the Admin role has ALL permissions in the system.
-- When new permissions are added via migrations, they need to be explicitly
-- granted to the Admin role. This migration fixes any gaps and should be
-- run after adding new permissions.
--
-- This is idempotent and safe to run multiple times.

-- ============================================================================
-- SYNC ADMIN ROLE PERMISSIONS
-- ============================================================================
-- The Admin role (00000000-0000-0000-0000-000000000001) should have all permissions.
-- This inserts any missing permission assignments.

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, p.id
FROM permissions p
WHERE NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = '00000000-0000-0000-0000-000000000001'::uuid
    AND rp.permission_id = p.id
);

-- ============================================================================
-- VERIFICATION (for logging purposes during migration)
-- ============================================================================
-- After this migration, the following should be true:
-- SELECT COUNT(*) FROM permissions = SELECT COUNT(*) FROM role_permissions
--                                     WHERE role_id = '00000000-0000-0000-0000-000000000001'
