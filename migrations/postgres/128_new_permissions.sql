-- Seed new permissions added in NAN-167 security sweep
-- detections:export (M8) and sessions:admin (H9)

INSERT INTO public.permissions (id, name, description, category)
VALUES
    ('detections:export', 'detections:export', 'Export detection rules', 'detections'),
    ('sessions:admin', 'sessions:admin', 'View and manage all user sessions', 'sessions')
ON CONFLICT (id) DO NOTHING;

-- Grant to Admin role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Admin'
  AND p.name IN ('detections:export', 'sessions:admin')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant detections:export to Editor role too
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Editor'
  AND p.name = 'detections:export'
ON CONFLICT (role_id, permission_id) DO NOTHING;
