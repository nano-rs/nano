-- Gate raw SQL search behind a dedicated permission (NAN-173)
-- Only Admin and Editor roles get this; ReadOnly cannot run raw SQL.

INSERT INTO public.permissions (id, name, description, category)
VALUES ('search:sql', 'search:sql', 'Execute raw SQL queries against ClickHouse', 'search')
ON CONFLICT (id) DO NOTHING;

-- Grant to Admin role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Admin'
  AND p.name = 'search:sql'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant to Editor role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Editor'
  AND p.name = 'search:sql'
ON CONFLICT (role_id, permission_id) DO NOTHING;
