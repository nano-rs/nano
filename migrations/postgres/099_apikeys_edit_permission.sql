-- Add apikeys:edit permission for update/enable/disable/reset operations
-- Previously these operations required apikeys:create which is overly broad

INSERT INTO permissions (id, name, description, category)
VALUES ('apikeys:edit', 'Edit API Keys', 'Update, enable, disable, and reset API keys', 'apikeys')
ON CONFLICT (id) DO NOTHING;

-- Grant apikeys:edit to all roles that currently have apikeys:create
-- (since those operations previously required apikeys:create, this preserves existing access)
INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, 'apikeys:edit'
FROM role_permissions rp
WHERE rp.permission_id = 'apikeys:create'
ON CONFLICT DO NOTHING;
