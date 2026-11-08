-- Migration: Prevalence Permissions
-- Description: Adds prevalence tracking permissions to the permissions table
-- 
-- This migration adds the prevalence:view, prevalence:configure, and prevalence:export
-- permissions that were defined in the Rust code but missing from the database.

-- ============================================================================
-- ADD PREVALENCE PERMISSIONS
-- ============================================================================
INSERT INTO permissions (id, name, description, category) VALUES
    ('prevalence:view', 'View Prevalence', 'View prevalence tracking data', 'prevalence'),
    ('prevalence:configure', 'Configure Prevalence', 'Configure prevalence tracking settings', 'prevalence'),
    ('prevalence:export', 'Export Prevalence', 'Export prevalence data', 'prevalence')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ASSIGN PREVALENCE PERMISSIONS TO ADMIN ROLE
-- ============================================================================
-- Admin role already gets all permissions via the SELECT from permissions table,
-- but we need to ensure the new permissions are assigned
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id FROM permissions
WHERE id IN ('prevalence:view', 'prevalence:configure', 'prevalence:export')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ASSIGN PREVALENCE VIEW TO EDITOR ROLE
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'prevalence:view'),
    ('00000000-0000-0000-0000-000000000002', 'prevalence:export')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ASSIGN PREVALENCE VIEW TO VIEWER ROLE
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000003', 'prevalence:view')
ON CONFLICT DO NOTHING;
