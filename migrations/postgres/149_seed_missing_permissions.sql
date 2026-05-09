-- Seed permissions that exist in Rust constants and are enforced in handlers
-- but were never added to the permissions table.
-- NAN-351: API key form missing permissions

INSERT INTO public.permissions (id, name, description, category) VALUES
    ('cases:comment', 'Comment on Cases', 'Add comments to cases', 'cases'),
    ('cases:share', 'Share Cases', 'Share cases with other users', 'cases'),
    ('upload:logs', 'Upload Logs', 'Upload log files for ingestion', 'upload'),
    ('upload:history', 'View Upload History', 'View log upload history and status', 'upload')
ON CONFLICT (id) DO NOTHING;

-- Grant to Admin role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Admin'
  AND p.id IN ('cases:comment', 'cases:share', 'upload:logs', 'upload:history')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant case permissions to Editor role (consistent with other case perms)
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Editor'
  AND p.id IN ('cases:comment', 'cases:share')
ON CONFLICT (role_id, permission_id) DO NOTHING;
