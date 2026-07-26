-- NAN-2125: separate credential metadata visibility from runtime secret use.
--
-- A caller may attach a credential to an integration, or deploy an integration
-- that already references one, only when it holds credentials:use. ReadOnly is
-- intentionally not granted this permission: viewing metadata must not confer
-- the ability to decrypt or publish stored credential material.

INSERT INTO permissions (id, name, description, category) VALUES
    (
        'credentials:use',
        'Use Credentials',
        'Attach or use stored credentials in runtime integrations',
        'credentials'
    )
ON CONFLICT (id) DO NOTHING;

-- Preserve the existing source-configuration workflows for the built-in
-- operator roles. Custom roles must opt in to this runtime-secret capability.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'credentials:use'
FROM roles r
WHERE r.id IN (
    '00000000-0000-0000-0000-000000000001', -- Admin
    '00000000-0000-0000-0000-000000000002'  -- Editor
)
ON CONFLICT DO NOTHING;
