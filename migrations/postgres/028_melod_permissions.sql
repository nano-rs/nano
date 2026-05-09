-- Add meloD AI assistant permissions
-- These control access to the AI-powered features like chat, query building,
-- detection generation, and dashboard creation

-- ============================================================================
-- INSERT MELOD PERMISSIONS
-- ============================================================================
INSERT INTO permissions (id, name, description, category) VALUES
    ('melod:chat', 'Chat with AI', 'Use AI chat and general assistance', 'melod'),
    ('melod:query', 'Build Queries', 'Use AI to build search queries from natural language', 'melod'),
    ('melod:parser', 'Create Parsers', 'Use AI to generate log parsers', 'melod'),
    ('melod:detection', 'Create Detections', 'Use AI to create and tune detection rules', 'melod'),
    ('melod:summarize', 'Summarize Results', 'Use AI to summarize search results', 'melod'),
    ('melod:dashboard', 'Generate Dashboards', 'Use AI to generate dashboard configurations', 'melod'),
    ('melod:notebook', 'Notebook AI', 'Use AI features in notebooks (timeline, suggestions)', 'melod')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ADMIN ROLE: Gets all permissions automatically via existing logic
-- (see 001_init_postgres.sql: "INSERT INTO role_permissions SELECT admin_id, id FROM permissions")
-- ============================================================================

-- ============================================================================
-- EDITOR ROLE: Grant all meloD permissions
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'melod:chat'),
    ('00000000-0000-0000-0000-000000000002', 'melod:query'),
    ('00000000-0000-0000-0000-000000000002', 'melod:parser'),
    ('00000000-0000-0000-0000-000000000002', 'melod:detection'),
    ('00000000-0000-0000-0000-000000000002', 'melod:summarize'),
    ('00000000-0000-0000-0000-000000000002', 'melod:dashboard'),
    ('00000000-0000-0000-0000-000000000002', 'melod:notebook')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- READONLY ROLE: Grant read-only AI features (chat, query, summarize)
-- Not: parser, detection, dashboard (these create/modify resources)
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000003', 'melod:chat'),
    ('00000000-0000-0000-0000-000000000003', 'melod:query'),
    ('00000000-0000-0000-0000-000000000003', 'melod:summarize')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- GRANT MELOD PERMISSIONS TO ADMIN ROLE
-- (ensures admin gets new permissions even if they already exist)
-- ============================================================================
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, id
FROM permissions
WHERE id LIKE 'melod:%'
ON CONFLICT DO NOTHING;
