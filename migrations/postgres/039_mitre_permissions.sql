-- Add MITRE ATT&CK framework permissions
-- These control access to view MITRE data and trigger syncs from GitHub

-- ============================================================================
-- INSERT MITRE PERMISSIONS
-- ============================================================================
INSERT INTO permissions (id, name, description, category) VALUES
    ('mitre:view', 'View MITRE Data', 'View MITRE ATT&CK tactics, techniques, and coverage', 'mitre'),
    ('mitre:sync', 'Sync MITRE Data', 'Trigger sync of MITRE ATT&CK data from GitHub', 'mitre')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ADMIN ROLE: Grant all MITRE permissions
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id
FROM permissions
WHERE id LIKE 'mitre:%'
ON CONFLICT DO NOTHING;

-- ============================================================================
-- EDITOR ROLE: Grant view and sync permissions
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'mitre:view'),
    ('00000000-0000-0000-0000-000000000002', 'mitre:sync')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- READONLY ROLE: Grant view-only access
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000003', 'mitre:view')
ON CONFLICT DO NOTHING;
