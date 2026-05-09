-- ============================================================================
-- Migration 093: Add Notebook Feature Permissions
-- ============================================================================
-- The notebooks feature was added in migration 004 but the corresponding
-- permissions were never created. The frontend checks notebooks:view etc.
-- but only melod:notebook (AI features in notebooks) existed.
-- ============================================================================

INSERT INTO permissions (id, name, description, category) VALUES
    ('notebooks:view', 'View Notebooks', 'View investigation notebooks', 'notebooks'),
    ('notebooks:create', 'Create Notebooks', 'Create new investigation notebooks', 'notebooks'),
    ('notebooks:edit', 'Edit Notebooks', 'Edit investigation notebooks', 'notebooks'),
    ('notebooks:delete', 'Delete Notebooks', 'Delete investigation notebooks', 'notebooks'),
    ('notebooks:share', 'Share Notebooks', 'Share investigation notebooks with others', 'notebooks')
ON CONFLICT (id) DO NOTHING;

-- Admin: full access
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000001', 'notebooks:view'),
    ('00000000-0000-0000-0000-000000000001', 'notebooks:create'),
    ('00000000-0000-0000-0000-000000000001', 'notebooks:edit'),
    ('00000000-0000-0000-0000-000000000001', 'notebooks:delete'),
    ('00000000-0000-0000-0000-000000000001', 'notebooks:share')
ON CONFLICT DO NOTHING;

-- Editor: view, create, edit, share (no delete)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'notebooks:view'),
    ('00000000-0000-0000-0000-000000000002', 'notebooks:create'),
    ('00000000-0000-0000-0000-000000000002', 'notebooks:edit'),
    ('00000000-0000-0000-0000-000000000002', 'notebooks:share')
ON CONFLICT DO NOTHING;

-- ReadOnly: view only
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000003', 'notebooks:view')
ON CONFLICT DO NOTHING;
